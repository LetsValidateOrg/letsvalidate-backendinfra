#!/usr/bin/python3

import logging
import datetime
import json
import uuid

import boto3

import letsvalidate.util.aws_apigw
import letsvalidate.util.aws_pgsql
import letsvalidate.util.user_state
import letsvalidate.util.aws_sqs


logger = logging.getLogger( "letsvalidate" )
logger.setLevel( logging.DEBUG )


def _validate_query_string_params(event, headers):
    if 'queryStringParameters' not in event or 'monitor_id' not in event['queryStringParameters']:
        return None

    # Make sure it has a proper value
    try:
        monitor_id = uuid.UUID(event['queryStringParameters']['monitor_id'])
    except ValueError:
        logger.warn(f"Monitor ID value of {event['queryStringParameters']['monitor_id']} was not a valid UUID")
        return None

    return str(monitor_id)


def _attempt_monitor_delete( db_cursor, user_id, monitor_id_to_delete ):

    # Take the monitor ID and work back to URL ID and Cert Issuer ID
    #       NOTE (SECURITY RISK): make sure to match on both monitor ID AND user, to make sure user
    #       doesn't try to delete a monitor they didn't create and do not own!!!
    db_cursor.execute("""
        SELECT      cert_issuers.cert_issuer_id_pk  AS cert_issuer_id,
                    urls.url_id_pk                  AS url_id
        FROM        monitored_urls
        JOIN        urls
            ON      monitored_urls.url_id = urls.url_id_pk 
        JOIN        cert_issuers
            ON      cert_issuers.cert_issuer_id_pk = urls.cert_issuer
        WHERE       monitored_urls.monitor_id_pk = %s
            AND     monitored_urls.cognito_user_id = %s;""",

        (monitor_id_to_delete, user_id) )

    full_details_row = db_cursor.fetchone()

    if full_details_row is None:
        return False

    issuer_id   = str(full_details_row[0])
    url_id      = str(full_details_row[1])

    # Find out how many certs use the issuer for this URL. If it's only 1, we can delete the issuer and it'll chain through and
    #   clean up URL *and* monitor
    db_cursor.execute("""
        SELECT      COUNT(url_id_pk)
        FROM        urls
        WHERE       cert_issuer = %s;""",

        (issuer_id,) )

    cert_issuer_count_row = db_cursor.fetchone()
    count_urls_with_this_issuer = cert_issuer_count_row[0]

    if count_urls_with_this_issuer == 1:
        logger.info(f"Can delete cert issuer and chain down through URL to monitor for monitor_id \"{monitor_id_to_delete}\"")

        db_cursor.execute("""
            DELETE FROM     cert_issuers
            WHERE           cert_issuer_id_pk = %s;""",

            (issuer_id,) )

        return True

    # If we get here, we can't delete the issuer as multiple URLs share an issuer, but we MAY be the only monitor for this
    #   URL. See if we can delete the entire URL, which chains through monitor
    db_cursor.execute("""
        SELECT      COUNT(monitor_id_pk)
        FROM        monitored_urls
        WHERE       url_id = %s;""",

        (url_id,) )

    url_monitor_count_row = db_cursor.fetchone()
    url_monitor_count = url_monitor_count_row[0]

    # If it's only one, delete the URL which will cascade to the single monitor as well
    if url_monitor_count == 1:

        logger.info(f"User \"{user_id}\" was the only user monitoring URL ID \"{url_id}\", but other certs have same issuer, deleting the entire URL" )

        db_cursor.execute("""
            DELETE FROM     urls
            WHERE           url_id_pk = %s;""",

        (url_id,) )

        return True

    # Just do the easy thing of deleting our monitor
    logger.info(f"Deleting \"{user_id}\" monitor on URL ID \"{url_id}\", leaving URL as others are watching it")
    db_cursor.execute("""
        DELETE FROM monitored_urls
        WHERE       monitor_id_pk = %s 
            AND     cognito_user_id = %s;""",

        (monitor_id_to_delete, user_id) )

    return True
        

def letsvalidate_api_remove_url(event, context):
    logger.debug( "Incoming event" )
    logger.debug( json.dumps(event, indent=4, sort_keys=True) )

    headers = {
        "content-type": "application/json",
    }

    monitor_id_to_delete = _validate_query_string_params(event, headers)

    if monitor_id_to_delete is None:
        status_code = 400

        body = {
            "error": "URL to did not include valid \"monitor_id\" URL query parameter"
        }

        return letsvalidate.util.aws_apigw.create_lambda_response( status_code, body, headers )

    # Have a valid monitor ID GUID to process
    user_id = event['requestContext']['authorizer']['jwt']['claims']['sub']
    logger.info(f"Cognito user \"{user_id}\" requested to delete monitor_id \"{monitor_id_to_delete}\"")

    with letsvalidate.util.aws_pgsql.get_db_handle() as db_handle:
        with db_handle.cursor() as db_cursor:

            if _attempt_monitor_delete( db_cursor, user_id, monitor_id_to_delete ):
        
                # Retrieve all updated user state
                user_state = letsvalidate.util.user_state.get_user_monitor_data( db_cursor, user_id )

                # Data timestamp
                data_timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat(sep=' ', timespec='seconds' )

                # Ship out the new user state to SQS so we don't hang up this API call any longer
                letsvalidate.util.aws_sqs.queue_json_for_workers_kv(user_id, user_state, data_timestamp )

                body = letsvalidate.util.aws_apigw.create_authoritative_user_state( user_state, data_timestamp )
                status_code = 200

                return letsvalidate.util.aws_apigw.create_lambda_response( status_code, body, headers )
            else:
                body = { "error": f"could not find monitor_id \"{monitor_id_to_delete}\" or current user does not have permission to remove it" }
                status_code = 404

                return letsvalidate.util.aws_apigw.create_lambda_response( status_code, body, headers )

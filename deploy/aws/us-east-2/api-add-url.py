#!/usr/bin/python3

import logging
import json
import boto3
import botocore.exceptions
import ssl
import OpenSSL
import datetime
import urllib.parse

import letsvalidate.util.aws_apigw
import letsvalidate.util.aws_pgsql
import letsvalidate.util.user_state
import letsvalidate.util.aws_sqs


logger = logging.getLogger( "letsvalidate" )
logger.setLevel( logging.DEBUG ) 


def letsvalidate_api_add_url(event, context):
    # Let's log event to see what we got
    logger.debug( "Incoming event:" )
    logger.debug( json.dumps(event, indent=4, sort_keys=True) )

    headers = {
        "content-type": "application/json",
    }

    body = None
    
    if 'queryStringParameters' not in event or 'url' not in event['queryStringParameters']:
        status_code = 400

        body = {
            "error": "URL to did not include \"url\" URL query parameter"
        }

        return letsvalidate.util.aws_apigw.create_lambda_response( status_code, body, headers )

    url_to_monitor = event['queryStringParameters']['url']

    user_cognito_id = _get_cognito_user_id(event)

    logger.info(f"Cognito user w/ ID {user_cognito_id} requested to monitor URL \"{url_to_monitor}\"")

    with letsvalidate.util.aws_pgsql.get_db_handle() as db_handle:
        with db_handle.cursor() as db_cursor:

            existing_url_info = _get_existing_url_info(db_cursor, url_to_monitor)

            if existing_url_info is not None:
                logger.info("Found existing info about this URL")
                # Is THIS user already monitoring it?
                if _user_already_monitoring(db_cursor, user_cognito_id, url_to_monitor):
                    logger.debug("User already monitoring this URL")
                    body = None
                    status_code = 204
                    return letsvalidate.util.aws_apigw.create_lambda_response(status_code, body, headers)

                logger.debug("User not monitoring this URL")
                # Add a monitor for this user, return them the data from last pull
                _add_monitor_for_user(db_cursor, user_cognito_id, url_to_monitor)

            else:
                logger.info("Found no existing data about this URL")

                # Pull its tls cert
                try:
                    cert_info = _do_tls_handshake(url_to_monitor)

                    # Add all database rows
                    _add_new_cert_with_monitor( db_cursor, url_to_monitor, cert_info, 
                        user_cognito_id )
        
                except Exception as e:
                    logger.warn("Unable to pull cert for URL: " + str(e))

                    status_code = 400
                    body = { "error": "Could not retrieve TLS certificate from URL \"" + url_to_monitor + "\"" }
                    return letsvalidate.util.aws_apigw.create_lambda_response(status_code, body, headers)

            # Retrieve all updated user state
            user_state = letsvalidate.util.user_state.get_user_monitor_data( db_cursor, user_cognito_id )

            # Data timestamp
            data_timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat(sep=' ', timespec='seconds' )

            # Ship out the new user state to SQS so we don't hang up this API call any longer
            letsvalidate.util.aws_sqs.queue_json_for_workers_kv(user_cognito_id, user_state, data_timestamp )

            body = letsvalidate.util.aws_apigw.create_authoritative_user_state( user_state, data_timestamp )

    if body is not None:
        status_code = 200
    else:
        body = {
            "error": "Inserted rows and monitor but got empty pull"
        }

        status_code = 500

    return letsvalidate.util.aws_apigw.create_lambda_response(status_code, body, headers)


def _user_already_monitoring(db_cursor, user_id, url):
    db_cursor.execute("""
        SELECT  monitor_id_pk
        FROM    monitored_urls
        JOIN    urls ON monitored_urls.url_id = urls.url_id_pk
        WHERE   monitored_urls.cognito_user_id = %s AND urls.url = %s;""",

        (user_id, url) )

    return db_cursor.fetchone() is not None


def _add_monitor_for_user(db_cursor, user_id, url):
    db_cursor.execute("""
        INSERT INTO monitored_urls (monitor_added, url_id, cognito_user_id) 
        VALUES ( 
            NOW(),
            (SELECT url_id_pk 
             FROM   urls
             WHERE  url = %s),
            %s );""",
        (url, user_id) )


def _get_existing_url_info(db_cursor, url_to_monitor):
    db_cursor.execute("""
        SELECT      cert_retrieved, cert_not_valid_before, cert_not_valid_after
        FROM        urls
        WHERE       url = %s;
        """, (url_to_monitor,) )
        
    return db_cursor.fetchone()


def _get_cognito_user_id(event):
    return event['requestContext']['authorizer']['jwt']['claims']['sub']


def _do_tls_handshake(url):
    # Get the hostname and port out of a URL
    parsed_uri = urllib.parse.urlparse(url)

    port_to_monitor = parsed_uri.port
    if port_to_monitor is None:
        port_to_monitor = 443
    host_dns_port = ( parsed_uri.hostname, port_to_monitor )

    logger.info( "Going to get TLS cert for " + json.dumps(host_dns_port) )

    server_cert = ssl.get_server_certificate( host_dns_port )

    # Decode the cert
    parsed_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM,
        str.encode(server_cert))
    #logger.info("Parsed server cert:")
    not_before = _parse_x509_date( parsed_cert.get_notBefore().decode() )
    not_after = _parse_x509_date( parsed_cert.get_notAfter().decode() )
    issuer = parsed_cert.get_issuer().organizationName
    subject = parsed_cert.get_subject().commonName

    cert_info = {
        "issuer"        : issuer,
        "subject"       : subject,
        "not_before"    : not_before,
        "not_after"     : not_after,
    }

    logger.info(json.dumps(cert_info, indent=4, sort_keys=True, default=str))
    return cert_info


def _parse_x509_date(date_string):

    no_timezone = datetime.datetime.strptime( date_string, '%Y%m%d%H%M%SZ' )

    # Set to UTC timezone
    with_timezone = no_timezone.replace(tzinfo=datetime.timezone.utc)

    return with_timezone


def _add_new_cert_with_monitor(db_cursor, url, cert_info, user_cognito_id ):
    # Let's see if this cert issuer is known
    db_cursor.execute("""
        SELECT cert_issuer_id_pk 
        FROM cert_issuers
        WHERE cert_issuer = %s;""",

        (cert_info['issuer'],) )

    cert_issuer_row = db_cursor.fetchone()

    if cert_issuer_row is not None:
        cert_issuer_id = cert_issuer_row[0]
    else:
        db_cursor.execute("""
            INSERT INTO cert_issuers (cert_issuer)
            VALUES ( %s )
            RETURNING cert_issuer_id_pk;""",

            (cert_info['issuer'],) )

        cert_issuer_id = db_cursor.fetchone()[0]

    db_cursor.execute("""
        INSERT INTO urls (url, cert_retrieved, cert_issuer, cert_subject, 
            cert_not_valid_before, cert_not_valid_after)
        VALUES ( %s, NOW(), %s, %s, %s, %s )
        RETURNING url_id_pk;""",

        (url, cert_issuer_id, cert_info['subject'], cert_info['not_before'],
            cert_info['not_after']) )

    # Get the ID for that new row
    new_url_id = db_cursor.fetchone()[0]

    db_cursor.execute("""
        INSERT INTO monitored_urls ( monitor_added, url_id, cognito_user_id )
        VALUES ( NOW(), %s, %s );""",

        (new_url_id, user_cognito_id) )

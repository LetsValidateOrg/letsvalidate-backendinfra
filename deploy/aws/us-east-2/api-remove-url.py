#!/usr/bin/python3

import logging
import letsvalidate.util.aws_apigw
import letsvalidate.util.aws_pgsql
import boto3
import json
import uuid


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


def _attempt_monitor_delete( user_id, monitor_id_to_delete ):
    with letsvalidate.util.aws_pgsql.get_db_handle() as db_handle:
        with db_handle.cursor() as db_cursor:
            pass
 

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

    _attempt_monitor_delete( user_id, monitor_id_to_delete )

    body = None
    status_code = 501

    return letsvalidate.util.aws_apigw.create_lambda_response( status_code, body, headers )

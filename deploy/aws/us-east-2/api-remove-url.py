#!/usr/bin/python3

import logging
import letsvalidate.util.aws_apigw
import boto3
import json
import uuid


logger = logging.getLogger( "letsvalidate" )
logger.setLevel( logging.DEBUG )

endpoint_region = "us-east-2"


boto3_clients = {
    'ssm'   : boto3.client( 'ssm', region_name=endpoint_region ),
}


def _validate_query_string_params(event, headers):
    if 'queryStringParameters' not in event or 'monitor_id' not in event['queryStringParameters']:
        return None

    # Make sure it has a proper value
    try:
        monitor_id = uuid.UUID(event['queryStringParameters']['monitor_id'])
    except ValueError:
        logger.warn("Monitor ID value of {event['queryStringParameters']['monitor_id']} was not a valid UUID")
        return None

    return str(monitor_id)


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

    body = None
    status_code = 501

    return letsvalidate.util.aws_apigw.create_lambda_response( status_code, body, headers )

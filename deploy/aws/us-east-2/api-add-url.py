#!/usr/bin/python3

import logging
import json
import boto3
import botocore.exceptions

logger = logging.getLogger()
logger.setLevel( logging.DEBUG ) 

endpoint_region = "us-east-2"

boto3_clients = {
    'ssm'   : boto3.client( 'ssm', region_name=endpoint_region ),
}

def letsvalidate_api_add_url(event, context):
    # Let's log event to see what we got
    logger.debug( "Incoming event:" )
    logger.debug( json.dumps(event, indent=4, sort_keys=True) )

    headers = {
        "content-type": "application/json",
    }
    
    if 'queryStringParameters' not in event or 'url' not in event['queryStringParameters']:
        status_code = 400

        body = {
            "error": "URL to did not include \"url\" URL query parameter"
        }

        return _create_lambda_response( status_code, body, headers )

    url_to_monitor = event['queryStringParameters']['url']

    logger.info(f"User requested to monitor URL \"{url_to_monitor}\"")

    body = None
    status_code = 200

    return _create_lambda_response(status_code, body, headers)


def _create_lambda_response( status_code, body, headers ):
    if body is not None:
        body_text = json.dumps(body, indent=4, sort_keys=True )
    else:
        body_text = None

    response = {
        "statusCode"    : status_code,
        "body"          : body_text,
    }

    if headers is not None:
        response['headers'] = headers

    return response


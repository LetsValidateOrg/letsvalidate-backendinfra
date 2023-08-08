#!/usr/bin/python3

import logging
import json
import boto3
import botocore.exceptions
import psycopg

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

    user_cognito_id = event['requestContext']['authorizer']['jwt']['claims']['sub']

    logger.info(f"Cognito user w/ ID {user_cognito_id} requested to monitor URL \"{url_to_monitor}\"")

    existing_url_info = _get_existing_url_info(url_to_monitor)

    if existing_url_info is not None:
        logger.info("Found existing info about this URL")

    body = {
        "requested_url": url_to_monitor,
    }
    status_code = 200

    return _create_lambda_response(status_code, body, headers)


def _get_existing_url_info(url_to_monitor):
    with _get_db_handle() as dbHandle:
        with dbHandle.cursor() as dbCursor:
            pass


def _get_db_handle():
    db_params = _get_ssm_db_parameters()
    logger.debug("DB params:")
    logger.debug(json.dumps(db_params, indent=4, sort_keys=True))

    return psycopg.connect(
        host        = db_params['dbhost'],
        user        = db_params['dbuser'],
        password    = db_params['dbpassword'],
        dbname      = db_params['dbname'] )
     

def _get_ssm_params( param_list ):
    returned_parameters = boto3_clients['ssm'].get_parameters( Names=param_list )

    ssm_params = {}

    for curr_param in returned_parameters['Parameters']:
        # Final component after slash will be key
        param_name = curr_param['Name'].split('/')[-1]
        ssm_params[param_name] = curr_param['Value']

    return ssm_params


def _get_ssm_db_parameters():

    param_store_keys = (
        "/letsvalidate/db/aws/us-east-2/dbname",
        "/letsvalidate/db/aws/us-east-2/dbhost",
        "/letsvalidate/db/aws/us-east-2/dbuser",
        "/letsvalidate/db/aws/us-east-2/dbpassword",
    )

    return _get_ssm_params( param_store_keys )


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


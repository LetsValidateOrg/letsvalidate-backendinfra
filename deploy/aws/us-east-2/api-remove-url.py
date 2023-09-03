#!/usr/bin/python3

import logging
import letsvalidate.util.aws_apigw
import boto3
import json


logger = logging.getLogger( "letsvalidate" )
logger.setLevel( logging.DEBUG )

endpoint_region = "us-east-2"


boto3_clients = {
    'ssm'   : boto3.client( 'ssm', region_name=endpoint_region ),
}


def letsvalidate_api_remove_url(event, context):
    logger.debug( "Incoming event" )
    logger.debug( json.dumps(event, indent=4, sort_keys=True) )

    headers = {
        "content-type": "application/json",
    }

    body = None
    status_code = 501

    return letsvalidate.util.aws_apigw.create_lambda_response( status_code, body, headers )

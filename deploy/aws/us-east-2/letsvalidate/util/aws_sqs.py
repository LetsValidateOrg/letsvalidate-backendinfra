#!/usr/bin/python3

import os
import boto3
import json
import logging
import letsvalidate.util.cf_workers_kv


# Example: https://github.com/serverless/examples/tree/v3/aws-python-sqs-worker

logger = logging.getLogger("letsvalidate")
logger.setLevel(logging.DEBUG)

endpoint_region = "us-east-2"

try:
    sqs_client
except NameError:
    # Turns out we haven't defined it yet, so get our handle
    sqs_client = boto3.client( 'sqs', region_name=endpoint_region )

try:
    sqs_queue_url
except NameError:
    sqs_queue_url = os.getenv('SQS_QUEUE_URL')


def queue_json_for_workers_kv(user_id, user_state, data_timestamp ):
    try: 
        message_body = {
            'user_id'           : user_id,
            'user_state'        : user_state,
            'data_timestamp'    : data_timestamp,
        }

        sqs_client.send_message(
            QueueUrl        = sqs_queue_url,
            MessageBody     = json.dumps(message_body, indent=4, sort_keys=True),
        )

        logger.info(f"Successfully sent SQS update with new user state for Worker KV on user \"{user_id}\"" )

        return True
    except Exception as e:
        logger.warn(f"Could not queue new JSON for Worker KV for user {user_id}: {str(e)}")
   
    return False


def queue_worker(event, context):
    for record in event['Records']:
        logger.info("SQS message received with Worker KV update data:") 

        kv_update_data = json.loads(record['body'])
        logger.info( json.dumps(kv_update_data, indent=4, sort_keys=True) )

        letsvalidate.util.cf_workers_kv.write_user_state( kv_update_data['user_id'], kv_update_data['user_state'],
            kv_update_data['data_timestamp'] )



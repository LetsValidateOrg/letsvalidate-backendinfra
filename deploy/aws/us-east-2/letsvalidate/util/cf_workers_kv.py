#!/usr/bin/python3

import logging
import datetime
import json

import workers_kv 

import letsvalidate.util.aws_ssm


logger = logging.getLogger( "letsvalidate" )
logger.setLevel( logging.DEBUG )


def _get_ssm_worker_kv_params():

    param_store_keys = (
        "/letsvalidate/cloudflare/cf_account_id",
        "/letsvalidate/cloudflare/db/workers_kv/workerskv_namespace_id",
        "/letsvalidate/cloudflare/cf_api_key",
    )

    return letsvalidate.util.aws_ssm.get_ssm_params( param_store_keys )


def _get_workers_kv_namespace():
    workers_kv_params = _get_ssm_worker_kv_params()

    #logger.info("Worker KV params")
    #logger.info(json.dumps(workers_kv_params, indent=4, sort_keys=True))

    return workers_kv.Namespace(
        account_id      = workers_kv_params['cf_account_id'],
        namespace_id    = workers_kv_params['workerskv_namespace_id'],
        api_key         = workers_kv_params['cf_api_key'] )


def write_user_state(user_cognito_id, monitored_cert_data):
    data_timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat(sep=' ', timespec='seconds' )

    # Push this out to worker KV
    workers_kv_key = f"user_state_{user_cognito_id}"

    # Create dict for Workers KV cache
    workers_kv_data = {
        'monitored_certificates'    : monitored_cert_data,
        'metadata': {
            'data_timestamp'        : data_timestamp,
            'authoritative_data'    : False,
        }
    }

    workers_kv_value = json.dumps(workers_kv_data, indent=2, sort_keys=True)
    try:
        workers_kv_namespace.write( { workers_kv_key: workers_kv_value } )
        logger.info(f"Successfully updated Workers KV for Cognito user {user_cognito_id}")
    except Exception as e:
        logger.warning( f"Could not update workers KV, exception thrown: \"{json.dumps(e, default=str)}\"" )


# Needs to be defined at the bottom as it calls functions higher up
workers_kv_namespace = _get_workers_kv_namespace()

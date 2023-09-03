#!/usr/bin/python3

import logging
import aws_ssm
import workers_kv


def _get_ssm_worker_kv_params(ssm_client):

    param_store_keys = (
        "/letsvalidate/cloudflare/cf_account_id",
        "/letsvalidate/cloudflare/db/workers_kv/workerskv_namespace_id",
        "/letsvalidate/cloudflare/cf_api_key",
    )

    return aws_ssm.get_ssm_params( ssm_client, param_store_keys )



def _get_workers_kv_namespace(ssm_client):
    workers_kv_params = _get_ssm_worker_kv_params(ssm_client)

    #logger.info("Worker KV params")
    #logger.info(json.dumps(workers_kv_params, indent=4, sort_keys=True))

    return workers_kv.Namespace(
        account_id      = workers_kv_params['cf_account_id'],
        namespace_id    = workers_kv_params['workerskv_namespace_id'],
        api_key         = workers_kv_params['cf_api_key'] )

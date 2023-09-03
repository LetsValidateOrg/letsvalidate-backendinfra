#!/usr/bin/python3

import boto3

endpoint_region = "us-east-2"

try:
    ssm_client
except NameError:
    # Turns out we haven't defined it yet, so get our handle
    ssm_client = boto3.client( 'ssm', region_name=endpoint_region )


def get_ssm_params( param_list ):
    returned_parameters = ssm_client.get_parameters( Names=param_list )

    ssm_params = {}

    for curr_param in returned_parameters['Parameters']:
        # Final component after slash will be key
        param_name = curr_param['Name'].split('/')[-1]
        ssm_params[param_name] = curr_param['Value']

    return ssm_params

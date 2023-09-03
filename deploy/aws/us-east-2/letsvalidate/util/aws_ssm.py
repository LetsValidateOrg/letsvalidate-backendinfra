#!/usr/bin/python3


def get_ssm_params( ssm_client, param_list ):
    returned_parameters = ssm_client.get_parameters( Names=param_list )

    ssm_params = {}

    for curr_param in returned_parameters['Parameters']:
        # Final component after slash will be key
        param_name = curr_param['Name'].split('/')[-1]
        ssm_params[param_name] = curr_param['Value']

    return ssm_params

#!/usr/bin/python3


import json


def create_lambda_response( status_code, body, headers ):
    if body is not None:
        body_text = json.dumps(body, indent=4, sort_keys=True)
    else:
        body_text = None

    response = {
        "statusCode"    : status_code,
        "body"          : body_text,
    }

    if headers is not None:
        response['headers'] = headers

    return response


def create_authoritative_user_state( user_state, data_timestamp ):
    authoritative_response = {
        'metadata'              : {
            'authoritative_data'    : True,
            'data_timestamp'        : data_timestamp,
            'api_endpoint'          : {
                'datacenter_iata_code'  : 'aws/cmh',
            }

        },
        'monitored_certificates'    : user_state,
    }

    return authoritative_response

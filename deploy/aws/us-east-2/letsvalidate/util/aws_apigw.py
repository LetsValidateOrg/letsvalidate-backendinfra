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

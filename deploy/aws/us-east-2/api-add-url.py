#!/usr/bin/python3

import logging
import json
import boto3
import botocore.exceptions
import psycopg
import ssl
import OpenSSL
import datetime


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

    user_cognito_id = _get_cognito_user_id(event)

    logger.info(f"Cognito user w/ ID {user_cognito_id} requested to monitor URL \"{url_to_monitor}\"")

    with _get_db_handle() as db_handle:
        with db_handle.cursor() as db_cursor:

            existing_url_info = _get_existing_url_info(db_cursor, url_to_monitor)

            if existing_url_info is not None:
                logger.info("Found existing info about this URL")
                # Is THIS user already monitoring it?
                if _user_already_monitoring(db_cursor, user_cognito_id, url_to_monitor):
                    logger.debug("User already monitoring this URL")
                    status_code = 204
                    body = None
                else:
                    logger.debug("User not monitoring this URL")
                    # Add a monitor for this user, return them the data from last pull
                    _add_monitor_for_user(db_cursor, 
                        user_cognito_id, url_to_monitor)
             
                    body = {
                        "cert_retrieved": existing_url_info[0].isoformat(),
                        "not_before": existing_url_info[1].isoformat(),
                        "not_after": existing_url_info[2].isoformat(),
                    }

                    status_code = 200
            else:
                logger.info("Found no existing data about this URL")

                # Pull its tls cert
                try:
                    cert_info = _do_tls_handshake(url_to_monitor)

                    # Add all database rows
                    _add_new_cert_with_monitor( db_cursor, url_to_monitor, cert_info, 
                        user_cognito_id )
                except Exception as e:
                    logger.warn("Unable to pull cert for URL: " + str(e))

                body = {
                    "status": "no existing data",
                }

                status_code = 200

    return _create_lambda_response(status_code, body, headers)


def _user_already_monitoring(db_cursor, user_id, url):
    db_cursor.execute("""
        SELECT  monitor_id_pk
        FROM    monitored_urls
        JOIN    urls ON monitored_urls.url_id = urls.url_id_pk
        WHERE   monitored_urls.cognito_user_id = %s AND urls.url = %s;""",

        (user_id, url) )

    return db_cursor.fetchone() is not None


def _add_monitor_for_user(db_cursor, user_id, url):
    db_cursor.execute("""
        INSERT INTO monitored_urls (monitor_added, url_id, cognito_user_id) 
        VALUES ( 
            NOW(),
            (SELECT url_id_pk 
             FROM   urls
             WHERE  url = %s),
            %s );""",
        (url, user_id) )


def _get_existing_url_info(db_cursor, url_to_monitor):
    db_cursor.execute("""
        SELECT      cert_retrieved, cert_not_valid_before, cert_not_valid_after
        FROM        urls
        WHERE       url = %s;
        """, (url_to_monitor,) )
        
    return db_cursor.fetchone()


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
        body_text = json.dumps(body, indent=4, sort_keys=True, default=str )
    else:
        body_text = None

    response = {
        "statusCode"    : status_code,
        "body"          : body_text,
    }

    if headers is not None:
        response['headers'] = headers

    return response


def _get_cognito_user_id(event):
    return event['requestContext']['authorizer']['jwt']['claims']['sub']

def _do_tls_handshake(url):
    server_cert = ssl.get_server_certificate( ('letsvalidate.org', 443) )

    # Decode the cert
    parsed_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM,
        str.encode(server_cert))
    #logger.info("Parsed server cert:")
    not_before = _parse_x509_date( parsed_cert.get_notBefore().decode() )
    not_after = _parse_x509_date( parsed_cert.get_notAfter().decode() )
    issuer = parsed_cert.get_issuer().organizationName
    subject = parsed_cert.get_subject().commonName

    cert_info = {
        "issuer"        : issuer,
        "subject"       : subject,
        "not_before"    : not_before,
        "not_after"     : not_after,
    }

    logger.info(json.dumps(cert_info, indent=4, sort_keys=True, default=str))
    return cert_info

def _parse_x509_date(date_string):

    no_timezone = datetime.datetime.strptime( date_string, '%Y%m%d%H%M%SZ' )

    # Set to UTC timezone
    with_timezone = no_timezone.replace(tzinfo=datetime.timezone.utc)

    return with_timezone


def _add_new_cert_with_monitor(db_cursor, url, cert_info, user_cognito_id ):
    # Let's see if this cert issuer is known
    db_cursor.execute("""
        SELECT cert_issuer_id_pk 
        FROM cert_issuers
        WHERE cert_issuer = %s;""",

        (cert_info['issuer'],) )

    cert_issuer_row = db_cursor.fetchone()

    if cert_issuer_row is not None:
        cert_issuer_id = cert_issuer_row[0]
    else:
        db_cursor.execute("""
            INSERT INTO cert_issuers (cert_issuer)
            VALUES ( %s )
            RETURNING cert_issuer_id_pk;""",

            (cert_info['issuer'],) )

        cert_issuer_id = db_cursor.fetchone()[0]

    db_cursor.execute("""
        INSERT INTO urls (url, cert_retrieved, cert_issuer, cert_subject, 
            cert_not_valid_before, cert_not_valid_after)
        VALUES ( %s, NOW(), %s, %s, %s, %s )
        RETURNING url_id_pk;""",

        (url, cert_issuer_id, cert_info['subject'], cert_info['not_before'],
            cert_info['not_after']) )

    # Get the ID for that new row
    new_url_id = db_cursor.fetchone()[0]

    db_cursor.execute("""
        INSERT INTO monitored_urls ( monitor_added, url_id, cognito_user_id )
        VALUES ( NOW(), %s, %s );""",

        (new_url_id, user_cognito_id) )
    
        

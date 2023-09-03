#!/usr/bin/python3

import logging
import json
import boto3
import botocore.exceptions
import psycopg
import ssl
import OpenSSL
import datetime
import workers_kv


logger = logging.getLogger( "letsvalidate" )
logger.setLevel( logging.DEBUG ) 

endpoint_region = "us-east-2"

boto3_clients = {
    'ssm'   : boto3.client( 'ssm', region_name=endpoint_region ),
}


def _get_ssm_params( param_list ):
    returned_parameters = boto3_clients['ssm'].get_parameters( Names=param_list )

    ssm_params = {}

    for curr_param in returned_parameters['Parameters']:
        # Final component after slash will be key
        param_name = curr_param['Name'].split('/')[-1]
        ssm_params[param_name] = curr_param['Value']

    return ssm_params


def _get_ssm_worker_kv_params():

    param_store_keys = (
        "/letsvalidate/cloudflare/cf_account_id",
        "/letsvalidate/cloudflare/db/workers_kv/workerskv_namespace_id",
        "/letsvalidate/cloudflare/cf_api_key",
    )

    return _get_ssm_params( param_store_keys )


def _get_workers_kv_namespace():
    workers_kv_params = _get_ssm_worker_kv_params() 

    #logger.info("Worker KV params")
    #logger.info(json.dumps(workers_kv_params, indent=4, sort_keys=True))

    return workers_kv.Namespace(
        account_id      = workers_kv_params['cf_account_id'],
        namespace_id    = workers_kv_params['workerskv_namespace_id'],
        api_key         = workers_kv_params['cf_api_key'] )


workers_kv_namespace = _get_workers_kv_namespace()


def letsvalidate_api_add_url(event, context):
    # Let's log event to see what we got
    logger.debug( "Incoming event:" )
    logger.debug( json.dumps(event, indent=4, sort_keys=True) )

    headers = {
        "content-type": "application/json",
    }

    body = None
    
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
                    body = None
                    status_code = 204
                    return _create_lambda_response(status_code, body, headers)

                logger.debug("User not monitoring this URL")
                # Add a monitor for this user, return them the data from last pull
                _add_monitor_for_user(db_cursor, user_cognito_id, url_to_monitor)

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

            # Get all data for this user
            monitored_cert_data = _get_user_monitor_data( db_cursor, user_cognito_id )
            data_timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat(sep=' ', timespec='seconds' )

            body = {
                'monitored_certificates'        : monitored_cert_data,
                'metadata' : {
                    'api_endpoint' : {
                        'datacenter_iata_code'  : 'aws/iad',
                    },
                    'data_timestamp'            : data_timestamp,
                    'authoritative_data'        : True,
                },
            }

            # Push this out to worker KV
            workers_kv_key = f"user_state_{user_cognito_id}"

            try:
                # Create similiar dict for Workers KV cache
                workers_kv_data = {
                    'monitored_certificates'    : monitored_cert_data,
                    'metadata': {
                        'data_timestamp'        : data_timestamp,
                        'authoritative_data'    : False,
                    }
                } 

                workers_kv_value = json.dumps(workers_kv_data, indent=2, sort_keys=True)

                #logger.debug(f"Writing to Workers KV key \"{workers_kv_key}\"" )
                #logger.debug(workers_kv_value)

                workers_kv_namespace.write( { workers_kv_key: workers_kv_value } )
                logger.info(f"Successfully updated Workers KV for Cognito user {user_cognito_id}")
            except Exception as e:
                logger.warning( f"Could not update workers KV, exception thrown: \"{json.dumps(e, default=str)}\"" )

    if body is not None:
        status_code = 200
    else:
        body = {
            "error": "Inserted rows and monitor but got empty pull"
        }

        status_code = 500

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


def _get_user_monitor_data(db_cursor, user_id):
    db_cursor.execute("""
        SELECT      monitored_urls.monitor_id_pk, urls.url, urls.cert_retrieved, urls.cert_not_valid_after, monitored_urls.last_alert_sent,
                    monitored_urls.next_alert_scheduled, monitored_urls.alert_muted
        FROM        urls
        JOIN        monitored_urls
        ON          urls.url_id_pk = monitored_urls.url_id 
            AND     monitored_urls.cognito_user_id = %s
        ORDER BY    urls.cert_not_valid_after;""",

        (user_id,) )

    user_monitor_data = []

    for curr_row in db_cursor.fetchall():
        user_data_row = {
            'monitor_id'        : str(curr_row[0]),
            'url'               : curr_row[1],
            'last_checked'      : curr_row[2].isoformat(sep=' ', timespec='seconds' ),
            'cert_expires'      : curr_row[3].isoformat(sep=' ', timespec='seconds' ),
        }

        if curr_row[4] is not None:
            user_data_row['last_alert'] = curr_row[4].isoformat(sep=' ', timespec='seconds' )

        if curr_row[5] is not None:
            user_data_row['next_alert'] = curr_row[5].isoformat(sep=' ', timespec='seconds' )
            user_data_row['alert_muted'] = False;

        elif curr_row[6] is not None:
            user_data_row['alert_muted'] = True

        user_monitor_data.append( user_data_row )

    return user_monitor_data



def _get_existing_url_info(db_cursor, url_to_monitor):
    db_cursor.execute("""
        SELECT      cert_retrieved, cert_not_valid_before, cert_not_valid_after
        FROM        urls
        WHERE       url = %s;
        """, (url_to_monitor,) )
        
    return db_cursor.fetchone()


def _get_db_handle():
    db_params = _get_ssm_db_parameters()
    #logger.debug("DB params:")
    #logger.debug(json.dumps(db_params, indent=4, sort_keys=True))

    return psycopg.connect(
        host        = db_params['dbhost'],
        user        = db_params['dbuser'],
        password    = db_params['dbpassword'],
        dbname      = db_params['dbname'] )
     


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

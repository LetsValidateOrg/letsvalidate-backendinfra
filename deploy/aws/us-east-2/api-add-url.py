#!/usr/bin/python3

import logging
import json
import boto3
import botocore.exceptions
import ssl
import OpenSSL
import datetime
import urllib.parse

import letsvalidate.util.aws_apigw
import letsvalidate.util.aws_pgsql
import letsvalidate.util.user_state
import letsvalidate.util.aws_sqs


logger = logging.getLogger( "letsvalidate" )
logger.setLevel( logging.DEBUG ) 


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

        return letsvalidate.util.aws_apigw.create_lambda_response( status_code, body, headers )

    url_to_monitor = event['queryStringParameters']['url']

    user_cognito_id = _get_cognito_user_id(event)

    logger.info(f"Cognito user w/ ID {user_cognito_id} requested to monitor URL \"{url_to_monitor}\"")

    with letsvalidate.util.aws_pgsql.get_db_handle() as db_handle:
        with db_handle.cursor() as db_cursor:

            existing_url_info = _get_existing_url_info(db_cursor, url_to_monitor)

            if existing_url_info is not None:
                logger.info("Found existing info about this URL")
                # Is THIS user already monitoring it?
                if _user_already_monitoring(db_cursor, user_cognito_id, url_to_monitor):
                    logger.debug("User already monitoring this URL")
                    body = None
                    status_code = 204
                    return letsvalidate.util.aws_apigw.create_lambda_response(status_code, body, headers)

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
                    raise e
                    logger.warn("Unable to pull cert for URL: " + str(e))

                    status_code = 400
                    body = { "error": "Could not retrieve TLS certificate from URL \"" + url_to_monitor + "\"" }
                    return letsvalidate.util.aws_apigw.create_lambda_response(status_code, body, headers)

            # Retrieve all updated user state
            user_state = letsvalidate.util.user_state.get_user_monitor_data( db_cursor, user_cognito_id )

            # Data timestamp
            data_timestamp = datetime.datetime.now(datetime.timezone.utc).isoformat(sep=' ', timespec='seconds' )

            # Ship out the new user state to SQS so we don't hang up this API call any longer
            letsvalidate.util.aws_sqs.queue_json_for_workers_kv(user_cognito_id, user_state, data_timestamp )

            body = letsvalidate.util.aws_apigw.create_authoritative_user_state( user_state, data_timestamp )

    if body is not None:
        status_code = 200
    else:
        body = {
            "error": "Inserted rows and monitor but got empty pull"
        }

        status_code = 500

    return letsvalidate.util.aws_apigw.create_lambda_response(status_code, body, headers)


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
        FROM        tls_certificates
        JOIN        urls
        ON          urls.tls_certificate = tls_certificates.cert_id_pk
        WHERE       url = %s;
        """, (url_to_monitor,) )
        
    return db_cursor.fetchone()


def _get_cognito_user_id(event):
    return event['requestContext']['authorizer']['jwt']['claims']['sub']


def parseX509Name(x509Name):

    # Info from: https://www.pyopenssl.org/en/latest/api/crypto.html#x509name-objects

    name_components = x509Name.get_components

    # Initialize so that all keys exist
    parsed_x509_name = {}

    x509_field_code_to_hash_code = {
        "C"     : 'countryName',
        "ST"    : 'stateOrProvinceName',
        "L"     : 'localityName',
        "O"     : 'organizationName',
        "OU"    : 'organizationalUnitName',
        "CN"    : 'commonName',

        # Apparently email has two mappings? 
        #    https://stackoverflow.com/a/42549270
        "E"             : 'emailAddress',
        "EMAILADDRESS"  : "emailAddress",
    }

    for expandedName in x509_field_code_to_hash_code.values():
        if expandedName not in parsed_x509_name:
            parsed_x509_name[ expandedName ] = None

    for curr_component_entry in x509Name.get_components():
        component_key       = curr_component_entry[0].decode()
        component_value     = curr_component_entry[1].decode()

        if component_key not in x509_field_code_to_hash_code:
            logger.warn("Got unknown x509 field in cert name: {component_key}, skipping")
            continue

        mapped_key = x509_field_code_to_hash_code[component_key]

        logger.debug(f"Got component entry ({component_key} => {mapped_key}, {component_value})")

        parsed_x509_name[mapped_key] = component_value
        
    return parsed_x509_name


def _do_tls_handshake(url):
    # Get the hostname and port out of a URL
    parsed_uri = urllib.parse.urlparse(url)

    port_to_monitor = parsed_uri.port
    if port_to_monitor is None:
        port_to_monitor = 443
    host_dns_port = ( parsed_uri.hostname, port_to_monitor )

    logger.info( "Going to get TLS cert for " + json.dumps(host_dns_port) )

    server_cert = ssl.get_server_certificate( host_dns_port )

    # Decode the cert
    parsed_cert = OpenSSL.crypto.load_certificate(OpenSSL.crypto.FILETYPE_PEM,
        str.encode(server_cert))
    #logger.info("Parsed server cert:")

    # https://www.pyopenssl.org/en/latest/api/crypto.html#x509-objects
    not_before                  = _parse_x509_date( parsed_cert.get_notBefore().decode() )
    not_after                   = _parse_x509_date( parsed_cert.get_notAfter().decode() )

    subject_info                = parseX509Name( parsed_cert.get_subject() )
    issuer_info                 = parseX509Name( parsed_cert.get_issuer() )

    cert_info = {
        "subject_info"          : subject_info,
        "issuer_info"           : issuer_info,
        "validity_range" : {
            "not_before"        : not_before,
            "not_after"         : not_after,
        },
        
        # Add this back in at some point when we find out why it's so busted
        # "serial_number"         : parsed_cert.get_serial_number(),
        "serial_number"         : None,
        "cert_version"          : parsed_cert.get_version(),
    }

    logger.info(json.dumps(cert_info, indent=4, sort_keys=True, default=str))
    return cert_info


def _parse_x509_date(date_string):

    no_timezone = datetime.datetime.strptime( date_string, '%Y%m%d%H%M%SZ' )

    # Set to UTC timezone
    with_timezone = no_timezone.replace(tzinfo=datetime.timezone.utc)

    return with_timezone


def _add_new_cert_with_monitor(db_cursor, url, cert_info, user_cognito_id ):
    logging.debug(f"Checking if we have an entry for this cert issuer: {cert_info['issuer_info']['commonName']}")
    # Let's see if this cert issuer is known
    db_cursor.execute("""
        SELECT cert_issuer_id_pk 
        FROM cert_issuers
        WHERE common_name = %s;""",

        (cert_info['issuer_info']['commonName'],) )

    cert_issuer_row = db_cursor.fetchone()

    if cert_issuer_row is not None:
        logging.debug(f"Found issuing cert with common name {{cert_info['issuer_info']['commonName']}}, returning the ID for the entry in the DB")
        cert_issuer_id = cert_issuer_row[0]
    else:
        logging.debug(f"No existing cert matching common name {cert_info['issuer_info']['commonName']}, adding new row")
        cert_issuer_info = cert_info['issuer_info']
        logging.debug("Issuer info")
        logging.debug(json.dumps(cert_issuer_info, indent=4, sort_keys=True) )
        db_cursor.execute("""
            INSERT INTO cert_issuers (common_name, country_name, email_address, locality_name,
                organization_name, organizational_unit_name, state_or_province )
            VALUES ( %s, %s, %s, %s, %s, %s, %s )
            RETURNING cert_issuer_id_pk;""",

            (cert_issuer_info['commonName'], cert_issuer_info['countryName'], cert_issuer_info['emailAddress'],
                cert_issuer_info['localityName'], cert_issuer_info['organizationName'], 
                cert_issuer_info['organizationalUnitName'], cert_issuer_info['stateOrProvinceName']))

        cert_issuer_id = db_cursor.fetchone()[0]

        logging.debug(f"New cert issuer ID: {cert_issuer_id}")

    cert_subject_info = cert_info['subject_info']

    logging.debug("Cert subject info")
    logging.debug(json.dumps(cert_subject_info, indent=4, sort_keys=True))

    db_cursor.execute("""
        INSERT INTO urls (url, cert_retrieved, cert_issuer, 

            cert_subject_common_name, cert_subject_country_name, cert_subject_email_address, 
            cert_subject_locality_name, cert_subject_organization_name, 
            cert_subject_organizational_unit_name, cert_subject_state_or_province,

            cert_not_valid_before, cert_not_valid_after,

            serial_number, cert_version)
        VALUES ( %s, NOW(), %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s )
        RETURNING url_id_pk;""",

        (url, cert_issuer_id, 

            cert_subject_info['commonName'], cert_subject_info['countryName'], 
            cert_subject_info['emailAddress'], cert_subject_info['localityName'],
            cert_subject_info['organizationName'], cert_subject_info['organizationalUnitName'],
            cert_subject_info['stateOrProvinceName'],

            cert_info['validity_range']['not_before'], cert_info['validity_range']['not_after'],

            cert_info['serial_number'], cert_info['cert_version']) 
    )

    # Get the ID for that new row
    new_url_id = db_cursor.fetchone()[0]

    logging.debug(f"New URL ID: {new_url_id}")

    db_cursor.execute("""
        INSERT INTO monitored_urls ( monitor_added, url_id, cognito_user_id )
        VALUES ( NOW(), %s, %s );""",

        (new_url_id, user_cognito_id) )

    logging.debug("Successfully added entry to monitored_urls")

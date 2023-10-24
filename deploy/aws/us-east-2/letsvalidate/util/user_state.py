#!/usr/bin/python3

def get_user_monitor_data(db_cursor, user_id):
    db_cursor.execute("""
        SELECT      monitored_urls.monitor_id_pk, urls.url, tls_certificates.cert_retrieved, 
                    tls_certificates.cert_not_valid_after, monitored_urls.last_alert_sent,
                    monitored_urls.next_alert_scheduled, monitored_urls.alert_muted,
                    cert_issuers.organization_name
        FROM        urls
        JOIN        monitored_urls
        ON          urls.url_id_pk = monitored_urls.url_id
            AND     monitored_urls.cognito_user_id = %s
        JOIN        tls_certificates
        ON          urls.tls_certificate = tls_certificates.cert_id_pk
        JOIN        cert_issuers
        ON          cert_issuers.cert_issuer_id_pk = tls_certificates.cert_issuer
        ORDER BY    tls_certificates.cert_not_valid_after;""",

        (user_id,) )

    user_monitor_data = []

    for curr_row in db_cursor.fetchall():
        user_data_row = {
            'monitor_id'        : str(curr_row[0]),
            'url'               : curr_row[1],
            'last_checked'      : curr_row[2].isoformat(sep=' ', timespec='seconds' ),
            'cert_expires'      : curr_row[3].isoformat(sep=' ', timespec='seconds' ),
            'cert_issuer_org'   : curr_row[7],
        }

        if curr_row[4] is not None:
            user_data_row['last_alert'] = curr_row[4].isoformat(sep=' ', timespec='seconds' )

        if curr_row[5] is not None:
            user_data_row['next_alert'] = curr_row[5].isoformat(sep=' ', timespec='seconds' )
            user_data_row['alert_muted'] = False;

        else:
            if curr_row[6] is not None:
                user_data_row['alert_muted'] = curr_row[6]
            else:
                user_data_row['alert_muted'] = False

        user_monitor_data.append( user_data_row )

    return user_monitor_data

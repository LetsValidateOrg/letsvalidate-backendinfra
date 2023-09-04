DROP TABLE monitored_urls CASCADE;
DROP TABLE cert_issuers CASCADE;
DROP TABLE urls;

CREATE TABLE cert_issuers (
    cert_issuer_id_pk       UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    cert_issuer             varchar         NOT NULL UNIQUE );

CREATE INDEX idx_cert_issuers_issuer ON cert_issuers(cert_issuer);


CREATE TABLE urls (
    url_id_pk               UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    url                     VARCHAR         NOT NULL UNIQUE,
    cert_retrieved          timestamp with time zone,
    cipher_suite            integer,
    cert_issuer             UUID            REFERENCES cert_issuers(cert_issuer_id_pk) ON DELETE CASCADE,
    cert_subject            varchar,
    cert_not_valid_before   timestamp with time zone,
    cert_not_valid_after    timestamp with time zone

);

CREATE INDEX idx_urls_url ON urls (url);

CREATE TABLE monitored_urls (
    monitor_id_pk           UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    monitor_added           timestamp with time zone NOT NULL,
    url_id                  UUID        NOT NULL REFERENCES urls(url_id_pk) ON DELETE CASCADE,
    cognito_user_id         UUID        NOT NULL,

    -- Optional fields
    last_alert_sent         timestamp with time zone,
    next_alert_scheduled    timestamp with time zone,
    alert_muted             boolean, 

    UNIQUE (url_id, cognito_user_id)
);

CREATE INDEX monitored_urls_idx_user_monitor_id     ON monitored_urls (monitor_id_pk, cognito_user_id);
CREATE INDEX monitored_urls_idx_url_id              ON monitored_urls (url_id);

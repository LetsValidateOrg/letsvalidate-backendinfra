DROP TABLE monitored_urls CASCADE;
DROP TABLE cert_issuers CASCADE;
DROP TABLE urls;

CREATE TABLE cert_issuers (
    cert_issuer_id_pk       UUID            PRIMARY KEY DEFAULT gen_random_uuid(),

    common_name                 varchar         NOT NULL,
    country_name                varchar,
    email_address               varchar,
    locality_name               varchar,
    organization_name           varchar,
    organizational_unit_name    varchar,
    state_or_province           varchar,

    UNIQUE (common_name, country_name, email_address, locality_name, organization_name,
        organizational_unit_name, state_or_province)
);

CREATE INDEX cert_issuers_idx_common_name ON cert_issuers(common_name);


CREATE TABLE urls (
    url_id_pk                               UUID            PRIMARY KEY DEFAULT gen_random_uuid(),
    url                                     VARCHAR NOT NULL UNIQUE,
    cert_retrieved                          timestamp with time zone        NOT NULL,
    cipher_suite                            integer,

    cert_issuer                             UUID            REFERENCES cert_issuers(cert_issuer_id_pk) ON DELETE CASCADE NOT NULL,

    cert_subject_common_name                varchar                         NOT NULL UNIQUE,
    cert_subject_country_name               varchar,
    cert_subject_email_address              varchar,
    cert_subject_locality_name              varchar,
    cert_subject_organization_name          varchar,
    cert_subject_organizational_unit_name   varchar,
    cert_subject_state_or_province          varchar,

    cert_not_valid_before                   timestamp with time zone        NOT NULL,
    cert_not_valid_after                    timestamp with time zone        NOT NULL,

    serial_number                           integer,
    cert_version                            integer,

    -- Will never have a duplicate entry for common name & version tuple 
    UNIQUE (cert_subject_common_name, cert_version)
);

CREATE INDEX urls_idx_url               ON urls (url);
CREATE INDEX urls_idx_cert_issuer       ON urls (cert_issuer);
CREATE INDEX urls_idx_cert_retrieved    ON urls (cert_retrieved);

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

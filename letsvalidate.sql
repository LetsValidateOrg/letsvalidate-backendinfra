DROP TABLE monitored_urls;
DROP TABLE urls;

CREATE TABLE urls (
    url_id_pk   UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    url         VARCHAR     NOT NULL UNIQUE
);

CREATE INDEX idx_urls_url ON urls (url);

CREATE TABLE monitored_urls (
    monitor_id_pk   UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    url_id          UUID        NOT NULL REFERENCES urls(url_id_pk),
    cognito_user_id UUID        NOT NULL,

    UNIQUE (url_id, cognito_user_id)
);

CREATE INDEX idx_monitored_urls_url ON monitored_urls (url_id);
CREATE INDEX idx_monitored_urls_user ON monitored_urls (cognito_user_id);

DROP TABLE monitored_urls;

CREATE TABLE monitored_urls (
    url_id_pk   UUID        PRIMARY KEY DEFAULT gen_random_uuid(),
    url         VARCHAR     NOT NULL UNIQUE
);

CREATE INDEX idx_monitored_urls_url ON monitored_urls (url);

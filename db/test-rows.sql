INSERT INTO urls (url, cert_retrieved, cert_not_valid_after) values ( 'https://expires-really-soon.test.letsvalidate.org/', '2023-08-26T00:09Z', '2023-08-29T23:59Z' );
insert into urls (url, cert_retrieved, cert_not_valid_after) values ( 'https://expires-soon.test.letsvalidate.org/', '2023-08-26T00:07Z', '2023-09-01T23:59Z' );
insert into urls (url, cert_retrieved, cert_not_valid_after) values ( 'https://expires-sorta-soon.test.letsvalidate.org/', '2023-08-26T00:05Z', '2023-09-23T23:59Z' );

insert into monitored_urls (monitor_added, url_id, cognito_user_id) values (now(), (SELECT url_id_pk FROM urls where url='https://expires-really-soon.test.letsvalidate.org/'), '11bb7550-a0c1-700b-c203-9cc563cc8415' );
insert into monitored_urls (monitor_added, url_id, cognito_user_id) values (now(), (SELECT url_id_pk FROM urls where url='https://expires-soon.test.letsvalidate.org/'), '11bb7550-a0c1-700b-c203-9cc563cc8415' );
insert into monitored_urls (monitor_added, url_id, cognito_user_id) values (now(), (SELECT url_id_pk FROM urls where url='https://expires-sorta-soon.test.letsvalidate.org/'), '11bb7550-a0c1-700b-c203-9cc563cc8415' );

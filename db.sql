create database 'test';
create table users (user char(255), pass char(255));
create table clients (id char(255), secret char(255));
create table authentication_code(client_id char(255), authcode char(255));
create table bearer_tokens(access_token char(255), refresh_token char(255), expires datetime, scopes char(255), client_id char(255));

-- interesting queries:
-- delete outdated bearer tokens -- delete from bearer_tokens where expires < now();

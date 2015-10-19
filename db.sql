create database 'test';
create table users (user char(255), pass char(255));
create table clients (id char(255), secret char(255), user char(255));
create table authentication_code(client_id char(31), authcode char(31));
create table bearer_tokens(access_token char(31), refresh_token char(31), expires datetime, scopes char(255), client_id char(255));

-- interesting queries:
-- delete outdated bearer tokens -- delete from bearer_tokens where expires < now();

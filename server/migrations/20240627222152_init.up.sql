-- Create users table.
create table if not exists users
(
    id integer primary key not null,
    username text not null unique,
    password text not null,
    pubkey blob not null,
    access_token blob null
);
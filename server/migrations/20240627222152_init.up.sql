-- Create users table.
create table if not exists users
(
    id integer primary key not null,
    username text not null unique,
    password text not null,
    pubkey blob not null
);

create table if not exists access_tokens
(
    id integer primary key not null,
    user_id integer not null,
    access_token blob not null,
    foreign key(user_id) references users(id) on delete cascade
);
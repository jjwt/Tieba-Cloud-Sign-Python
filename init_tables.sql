CREATE TABLE if not exists user (
    user_id integer primary key autoincrement,
    username varchar(20) unique not null,
    pwd_hash varchar(64) not null,
    salt varchar(64) not null,
    role integer default 1, -- 0 -> admin, 1 -> commom_user
    banned integer default 0 -- 0 -> active, 1 -> deactive
);

-- persistent cookie storage
CREATE TABLE if not exists persis_token (
    user_id integer not null,
    token varchar(128) not null, -- pattern 128_random_chars
    expire_time integer not null, 
    deleted integer default 0
);

-- login error count limit storage
CREATE TABLE if not exists login_err (
    ip varchar(20) not null,
    err_count integer not null,
    expire_time integer not null,
    deleted integer default 0
);

CREATE TABLE if not exists user_tbuser (
    id integer primary key autoincrement,
    user_id integer not null, 
    tbuser_name varchar(30) unique not null,
    bduss varchar(60),
    bduss_ok integer default 0
);

CREATE TABLE if not exists tieba_list (
    tbuser_name varchar(30) not null,
    tb_name varchar(30) not null,
    tb_id varchar(30) not null,
    signed integer default 0
);

CREATE TABLE if not exists sign_records (
    tbuser_name varchar(30) not null,
    tb_name varchar(30) not null,
    sign_date varchar(8), -- like 20150102
    err_no integer default 1 -- err_no from baidu
);

-- dayly refresh tieba_list task
CREATE TABLE if not exists todo_updatetblist (
    finish_date varchar(8) -- like 20150102
);

CREATE TABLE if not exists todo_delcookiefile (
    filename varchar(30) not null,
    expire_time integer not null,
    deleted integer default 0
);

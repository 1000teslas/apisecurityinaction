CREATE USER natter_api_user PASSWORD 'password';     

CREATE TABLE users(
    user_id VARCHAR(30) PRIMARY KEY,
    pw_hash VARCHAR(255) NOT NULL
);
GRANT SELECT, INSERT ON users TO natter_api_user;

CREATE TABLE spaces(            
    space_id INT PRIMARY KEY,
    name VARCHAR(255) NOT NULL,
    owner VARCHAR(30) NOT NULL
);
CREATE SEQUENCE space_id_seq;    
GRANT SELECT, INSERT ON spaces TO natter_api_user;
CREATE UNIQUE INDEX space_name_idx ON spaces(name);

CREATE TABLE messages(                                 
    space_id INT NOT NULL REFERENCES spaces(space_id),
    msg_id INT PRIMARY KEY,
    author VARCHAR(30) NOT NULL REFERENCES users(user_id),
    msg_time TIMESTAMP NOT NULL DEFAULT CURRENT_TIMESTAMP,
    msg_text VARCHAR(1024) NOT NULL
);
CREATE SEQUENCE msg_id_seq;
CREATE INDEX msg_timestamp_idx ON messages(msg_time);    
GRANT SELECT, INSERT, DELETE ON messages TO natter_api_user;

CREATE TABLE audit_log(
    audit_id INT NULL,
    method VARCHAR(10) NOT NULL,
    path VARCHAR(100) NOT NULL,
    user_id VARCHAR(30) NULL,
    status INT NULL,
    audit_time TIMESTAMP NOT NULL
);
CREATE SEQUENCE audit_id_seq;
GRANT SELECT, INSERT ON audit_log to natter_api_user;

CREATE TABLE tokens(
    token_id VARCHAR(100) PRIMARY KEY,
    user_id VARCHAR(30) NOT NULL REFERENCES users(user_id),
    expiry TIMESTAMP NOT NULL,
    attributes VARCHAR(4096) NOT NULL     
);
GRANT SELECT, INSERT, DELETE ON tokens TO natter_api_user;
CREATE INDEX expired_token_idx ON tokens(expiry);

CREATE TABLE caps(
    cap_id VARCHAR(100) PRIMARY KEY,
    path VARCHAR(100) NOT NULL,
    r BOOLEAN NOT NULL,
    w BOOLEAN NOT NULL,
    d BOOLEAN NOT NULL
);
GRANT SELECT, INSERT, DELETE ON caps TO natter_api_user;

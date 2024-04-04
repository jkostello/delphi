-- Creates the database
CREATE database if not exists PasswordDatabase;

-- Uses the new database for creating the tables to hold data
Use PasswordDatabase;

-- create table for users
create table if not exists users (
	user_id int unsigned auto_increment primary key,
	username varchar(255),
	user_master_password varchar(255),
	password_hash varchar(255),
	token varchar(255)
    );
    
-- create table for passwords
create table if not exists passwords (
	passwords_id int unsigned auto_increment primary key,
	user_id int unsigned not null,
	username varchar(255) not null,
	user_password varchar(255) not null,
	website varchar(255) not null
    );

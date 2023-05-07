-- Add migration script here
CREATE TABLE users (
  email VARCHAR(100) NOT NULL UNIQUE PRIMARY KEY,
  hash VARCHAR(122) NOT NULL,
  created_at TIMESTAMP NOT NULL
);
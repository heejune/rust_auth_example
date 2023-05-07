-- Add migration script here
CREATE TABLE invitations (
  id UUID NOT NULL UNIQUE PRIMARY KEY,
  email VARCHAR(100) NOT NULL,
  expires_at TIMESTAMP NOT NULL
);
-- Runs once, on first boot of the db container.
-- The test suite needs a database it can freely create and drop schema in.
CREATE DATABASE threatlens_test OWNER threatlens;

\connect threatlens
CREATE EXTENSION IF NOT EXISTS vector;

\connect threatlens_test
CREATE EXTENSION IF NOT EXISTS vector;

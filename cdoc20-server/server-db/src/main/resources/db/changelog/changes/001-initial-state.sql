-- liquibase formatted sql
-- changeset initial-state:1
CREATE TABLE cdoc2_capsule (
    transaction_id VARCHAR(34) NOT NULL,
    recipient bytea NOT NULL,
    payload bytea NOT NULL,
    capsule_type VARCHAR(50) NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE NOT NULL,
    CONSTRAINT pk_cdoc2_capsule PRIMARY KEY (transaction_id)
);


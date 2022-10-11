-- liquibase formatted sql
-- generated with JPA Buddy
-- changeset jkusman:1661520137912-1
CREATE TABLE server_ecc_details (
    transaction_id VARCHAR(34) NOT NULL,
    recipient_pub_key VARCHAR(255) NOT NULL,
    sender_pub_key VARCHAR(255) NOT NULL,
    ecc_curve SMALLINT NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE,
    CONSTRAINT pk_server_ecc_details PRIMARY KEY (transaction_id));


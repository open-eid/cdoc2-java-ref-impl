#!/usr/bin/env bash

# All certs listed here:
# https://www.skidsolutions.eu/resources/certificates/#Test-certificates

# tsp.demo.sk.ee TLS cer
wget https://c.sk.ee/tsp_demo_sk_ee_2025.pem.cer

# Mobile-ID demo issuer certs
# https://github.com/SK-EID/PKI/wiki/Certification-Hierarchy#what-will-change-in-ca-hierarchy
wget https://www.skidsolutions.eu/upload/files/TEST_EID-Q_2021E.pem.crt
wget https://www.skidsolutions.eu/upload/files/TEST%20of%20EID-SK%202016_reissued.pem
wget https://www.sk.ee/upload/files/TEST_of_ESTEID-SK_2015.pem.crt
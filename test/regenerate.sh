#!/bin/bash
set -eu

openssl req -x509 -sha256 -days 800 -newkey rsa:2048 -nodes \
    -config openssl.cnf \
    -subj "/C=AU/ST=Some-State/O=Internet Widgits Pty Ltd" \
    -keyout root-key.pem \
    -out root-ca.pem

openssl req -sha256 -newkey rsa:2080 -nodes \
    -config openssl.cnf \
    -subj "/C=AU/ST=Some-State/O=Internet Widgits Pty Ltd" \
    -keyout key.pem \
    -out csr.pem

openssl x509 -req -days 800 \
    -extensions v3_req \
    -extfile openssl.cnf \
    -CA root-ca.pem \
    -CAkey root-key.pem \
    -CAcreateserial \
    -in csr.pem \
    -out cert.pem

openssl pkcs12 -export \
    -CAfile root-ca.pem \
    -inkey key.pem \
    -in cert.pem \
    -certfile root-ca.pem \
    -out identity.p12 \
    -passout pass:mypass

openssl x509 -outform der -in root-ca.pem -out root-ca.der
openssl x509 -outform der -in cert.pem -out cert.der

rm root-ca.srl root-key.pem csr.pem key.pem

# Generate Alice's Key Pair without passphrase
openssl genpkey -algorithm RSA -out alice_private.key -aes256 -pass pass:
openssl rsa -pubout -in alice_private.key -out alice_public.pem

# Generate Bob's Key Pair without passphrase
openssl genpkey -algorithm RSA -out bob_private.key -aes256 -pass pass:
openssl rsa -pubout -in bob_private.key -out bob_public.pem

# Generate Bank's Key Pair without passphrase
openssl genpkey -algorithm RSA -out bank_private.key -aes256 -pass pass:
openssl rsa -pubout -in bank_private.key -out bank_public.pem

# Create the Bank's Self-Signed Certificate
openssl req -x509 -new -key bank_private.key -out bank_cert.crt -days 365

# Create Alice's Certificate Signing Request (CSR)
openssl req -new -key alice_private.key -out alice.csr

# Create a configuration file for certificate signing
echo "subjectAltName=email:alice@example.com" > alice_cert_config.cnf

# Sign Alice's CSR with the Bank's private key to obtain the certificate
openssl x509 -req -days 365 -in alice.csr -CA bank_cert.crt -CAkey bank_private.key -CAcreateserial -out alice_cert.crt -extfile alice_cert_config.cnf




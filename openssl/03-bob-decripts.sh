# Create folder for Bob's output
mkdir -p bobs

# Verify Alice's Identity
openssl dgst -sha256 -verify ./bobs/alice_public.pem -signature encrypted_message.sha256 encrypted_message.bin

# Trust Alice's certificate because we trust the Bank
openssl verify -CAfile bank_cert.crt alice_cert.crt

# Extract Alice's public key from the certificate
openssl x509 -in alice_cert.crt -pubkey -noout > ./bobs/alice_public.pem

# Decrypt the Message
openssl rsautl -decrypt -inkey bob_private.key -in encrypted_message.bin -out ./bobs/decrypted_message.txt
# Encrypt the message using Bob's public key
openssl rsautl -encrypt -pubin -inkey bob_public.pem -in plaintext_message.txt -out encrypted_message.bin

# Sign the encrypted message using Alice's private key
openssl dgst -sha256 -sign alice_private.key -out encrypted_message.sha256 encrypted_message.bin
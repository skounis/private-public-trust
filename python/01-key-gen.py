# Python code for key generation
from OpenSSL import crypto

def generate_key_pair(file_path):
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)

    # Save the key pair to a file
    with open(file_path, 'wb') as f:
        f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, key))
        f.write(crypto.dump_publickey(crypto.FILETYPE_PEM, key))

# Generate key pairs for Alice and Bob
generate_key_pair('alice_private_key.pem')
generate_key_pair('bob_private_key.pem')
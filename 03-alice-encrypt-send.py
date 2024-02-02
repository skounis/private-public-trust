# Python code for encryption and sending by Alice with CMS
# Install the cms library: 
#  pip install cms
from OpenSSL import crypto
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes

def sign_message(message, sender_private_key_path):
    try:
        # Load Alice's private key
        print("Load Alice's private key: ", sender_private_key_path)
        with open(sender_private_key_path, 'rb') as f:
            sender_private_key_data = f.read()

        # Sign the message using Alice's private key
        private_key = load_pem_private_key(sender_private_key_data, password=None, backend=default_backend())
        signature = private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())

        return signature
    except FileNotFoundError:
        print("(sign_message) File not found. Please provide correct file paths.")

def encrypt_message(message, recipient_public_key_path):
    try:
        # Load Bob's public key
        print("Load Bob's public key: ", recipient_public_key_path)
        with open(recipient_public_key_path, 'rb') as f:
            recipient_public_key_data = f.read()
        
        recipient_public_key = serialization.load_pem_public_key(recipient_public_key_data, backend=default_backend())

        # Encrypt the message using Bob's public key
        encrypted_message = recipient_public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return encrypted_message
    except FileNotFoundError:
        print("(encrypt_message) File not found. Please provide correct file paths.")

def create_cms(encrypted_message, signature):
    try:
        signers = [
            SignedData.SignerInfo(
                signer_identifier=bytes(sender_certificate.subject),
                signed_attrs=[
                    SignedData.SignedAttribute(
                        oid=SignedData.CMSAttributeType.message_digest,
                        values=[hashes.Hash(hashes.SHA256(), encrypted_message).digest()]
                    ),
                ],
                signature_algorithm=SignedData.RSASignatureAlgorithm(
                    padding.PKCS1v15(), hashes.SHA256()
                ),
                signature=signature,
            )
        ]

        cms_data = SignedData(
            data=encrypted_message,
            signers=signers,
        )

        with open('alice_message.cms', 'wb') as f:
            f.write(cms_data.dump())
        print("CMS created and saved as 'alice_message.cms'")
    except Exception as e:
        print("Error creating CMS:", e)

# Example usage
if __name__ == "__main__":
    message = b"Hello Bob, this is a confidential message for you."
    sender_private_key_path = 'alice_private_key.pem'
    recipient_public_key_path = 'bob_certificate.pem' #'bob_public_key.pem'

    signature = sign_message(message, sender_private_key_path)
    encrypted_message = encrypt_message(message, recipient_public_key_path)
    create_cms(encrypted_message, signature)
    print("Encrypted message:", encrypted_message)
    print("Signature:", signature)
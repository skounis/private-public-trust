# A Practical Guide: Secure Information Sharing Using Private/Public Keys and Trusted Certificates

## Introduction

In today's digital age, ensuring the security and privacy of sensitive information is paramount. Cryptographic tools play a crucial role in achieving this goal, offering a robust framework for secure communication. In this article, we'll explore the fundamentals of secure information sharing using private/public keys and trusted certificates. By the end, you'll have a clear understanding of how these tools work together to facilitate secure and verifiable communication.

### Background Information
* **Private/Public Key Cryptography**: This asymmetric cryptographic technique involves the use of a pair of keys – a private key kept secret and a public key shared openly. Messages encrypted with the public key can only be decrypted with the corresponding private key and vice versa.

* **Trusted Certificates**: Certificates, issued by trusted authorities, serve as digital credentials that bind a public key to an entity, such as an individual or an organization. These certificates are crucial for establishing trust in the authenticity of public keys.

### Rationale and Need for a Trusted Authority
* **Trust in Digital Communication**: In the digital realm, establishing trust is challenging. Without a reliable mechanism to verify the identity of communicating parties, malicious actors could impersonate legitimate entities, leading to security breaches.

* **Role of a Trusted Authority**: Trusted authorities, often referred to as Certificate Authorities (CAs), play a pivotal role. They validate the identity of certificate holders before issuing certificates. These certificates, in turn, vouch for the authenticity of the associated public keys.

## Generating Private/Public Keys

Before delving into the intricacies of cryptographic communication, let's first understand the concept of private and public keys. In asymmetric cryptography, each entity possesses a unique pair of keys: a private key and a corresponding public key. The private key is kept secret and used for encryption and digital signing, while the public key is shared openly and used for decryption and signature verification.

### How to Generate Keys

To generate a key pair, cryptographic libraries like OpenSSL or programming languages such as Python or JavaScript provide convenient tools. Here's a basic example of how to generate a key pair using OpenSSL in the command line:

```bash
openssl genpkey -algorithm RSA -out private_key.pem
openssl rsa -pubout -in private_key.pem -out public_key.pem
```

This generates a private key (`private_key.pem`) and its corresponding public key (`public_key.pem`) in PEM format.

## Importance of Trusted Certificates

While public keys can be freely shared, ensuring their authenticity is crucial. This is where trusted certificates come into play. Certificates are digital documents issued by trusted entities, such as Certificate Authorities (CAs) or banks, that bind a public key to a specific identity. By verifying the issuer's signature on the certificate, parties can trust the association between the public key and its owner.

### Creating a Trusted Certificate

Let's consider a scenario where a bank issues a certificate to verify the identity of an individual. The process typically involves the following steps:

1. The individual submits their public key to the bank for verification.
2. The bank conducts identity verification procedures to ensure the authenticity of the requester.
3. Upon successful verification, the bank signs the individual's public key with its private key, creating a certificate that links the public key to the holder's identity.

Before creating a certificate, let's first understand the ".pem" files. ".pem" (Privacy-Enhanced Mail) files are commonly used to store cryptographic objects such as keys and certificates. They are encoded in Base64 and are often used for key exchange between systems.

To generate a private key and a self-signed certificate using OpenSSL, follow these steps:

1. Generate a private key:
```bash
openssl genpkey -algorithm RSA -out bank_private_key.pem
```

2. Generate a self-signed certificate using the private key:
```bash
openssl req -new -x509 -key bank_private_key.pem -out bank_certificate.pem -days 365
```

Now that we have the bank's private key and certificate, we can proceed with creating a certificate signed by the bank.

```python
# Python code to generate a key pair and create a certificate signed by the bank
from OpenSSL import crypto
import os

# Function to generate key pair
def generate_key_pair():
    key = crypto.PKey()
    key.generate_key(crypto.TYPE_RSA, 2048)
    return key

# Function to create a certificate signed by the bank
def create_certificate(holder_public_key):
    # Generate bank's private key and certificate if not already present
    if not os.path.isfile('bank_private_key.pem') or not os.path.isfile('bank_certificate.pem'):
        bank_key = generate_key_pair()
        bank_cert = crypto.X509()
        bank_cert.set_pubkey(bank_key)
        bank_cert.gmtime_adj_notBefore(0)
        bank_cert.gmtime_adj_notAfter(31536000)  # 1 year validity
        bank_cert.sign(bank_key, 'sha256')

        # Save bank's private key and certificate to files
        with open('bank_private_key.pem', 'wb') as f:
            f.write(crypto.dump_privatekey(crypto.FILETYPE_PEM, bank_key))
        with open('bank_certificate.pem', 'wb') as f:
            f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, bank_cert))

    # Load bank's private key and certificate
    with open('bank_private_key.pem', 'rb') as f:
        bank_private_key = f.read()
    with open('bank_certificate.pem', 'rb') as f:
        bank_certificate = f.read()

    # Create an X.509 certificate object
    cert = crypto.X509()
    cert.set_pubkey(holder_public_key)

    # Set certificate's subject and issuer information (for demonstration purposes)
    cert.get_subject().CN = "Holder's Identity"
    cert.set_issuer(crypto.load_certificate(crypto.FILETYPE_PEM, bank_certificate).get_subject())

    # Set validity period (for demonstration purposes)
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(31536000)  # 1 year validity

    # Sign the certificate using the bank's private key
    cert.sign(crypto.load_privatekey(crypto.FILETYPE_PEM, bank_private_key), 'sha256')

    return cert

# Generate key pair for the holder
holder_private_key = generate_key_pair()
holder_public_key = holder_private_key.to_cryptography_key().public_key()

# Create a certificate signed by the bank
holder_certificate = create_certificate(holder_public_key)

```

## Examples and Use Cases

Now that we understand the basics of private/public keys and trusted certificates, let's explore some practical examples and use cases.

### Key Generation
We'll start by generating private/public key pairs for both Alice and Bob.

```python
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
```

### Certificate Creation
With the key pairs in place, the next step is to create certificates for Alice and Bob issued by a trusted authority. These certificates will establish the authenticity of their public keys.

```python
# Python code for certificate creation
from OpenSSL import crypto

def create_certificate(subject_name, issuer_certificate_path, issuer_private_key_path, file_path):
    issuer_cert = crypto.load_certificate(crypto.FILETYPE_PEM, open(issuer_certificate_path, 'rb').read())
    issuer_key = crypto.load_privatekey(crypto.FILETYPE_PEM, open(issuer_private_key_path, 'rb').read())

    cert = crypto.X509()
    cert.set_serial_number(1)
    cert.set_subject(subject_name)
    cert.set_issuer(issuer_cert.get_subject())
    cert.set_pubkey(issuer_cert.get_pubkey())
    cert.gmtime_adj_notBefore(0)
    cert.gmtime_adj_notAfter(315360000)  # Valid for 10 years
    cert.sign(issuer_key, 'sha256')

    # Save the certificate to a file
    with open(file_path, 'wb') as f:
        f.write(crypto.dump_certificate(crypto.FILETYPE_PEM, cert))

# Create certificates for Alice and Bob
create_certificate(crypto.X509Name(b'CN=Alice'), 'bank_certificate.pem', 'bank_private_key.pem', 'alice_certificate.pem')
create_certificate(crypto.X509Name(b'CN=Bob'), 'bank_certificate.pem', 'bank_private_key.pem', 'bob_certificate.pem')
```

### Use Case 1: Encryption and Sending by Alice

Now, let's explore how Alice can securely send a confidential message to Bob. She'll encrypt the message using Bob's public key, sign it with her private key, and encapsulate both in a CMS (Cryptographic Message Syntax) structure.

```python
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
        with open(sender_private_key_path, 'rb') as f:
            sender_private_key_data = f.read()

        # Sign the message using Alice's private key
        private_key = load_pem_private_key(sender_private_key_data, password=None, backend=default_backend())
        signature = private_key.sign(message, padding.PKCS1v15(), hashes.SHA256())

        return signature
    except FileNotFoundError:
        print("File not found. Please provide correct file paths.")

def encrypt_message(message, recipient_public_key_path):
    try:
        # Load Bob's public key
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
        print("File not found. Please provide correct file paths.")

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
    recipient_public_key_path = 'bob_public_key.pem'

    signature = sign_message(message, sender_private_key_path)
    encrypted_message = encrypt_message(message, recipient_public_key_path)
    create_cms(encrypted_message, signature)
    print("Encrypted message:", encrypted_message)
    print("Signature:", signature)

```

### Use Case 2: Verification of Certificate and Digital Signature by Bob

Bob receives a CMS containing the encrypted message and Alice's digital signature. He verifies the authenticity of Alice's certificate and the integrity of the message using the digital signature within the CMS.

```python
# Python code for certificate and signature verification by Bob
from OpenSSL import crypto

def verify_certificate(sender_certificate_path, trusted_certificate_path):
    try:
        # Load Alice's certificate and the trusted certificate (e.g., from a bank)
        sender_certificate_data = open(sender_certificate_path, 'rb').read()
        trusted_certificate_data = open(trusted_certificate_path, 'rb').read()

        sender_certificate = crypto.load_certificate(crypto.FILETYPE_PEM, sender_certificate_data)
        trusted_certificate = crypto.load_certificate(crypto.FILETYPE_PEM, trusted_certificate_data)

        # Create a certificate store and add the trusted certificate
        store = crypto.X509Store()
        store.add_cert(trusted_certificate)

        # Create a certificate context and set the store
        context = crypto.X509StoreContext(store, sender_certificate)

        # Verify the certificate chain
        context.verify_certificate()

        print("Certificate verification successful!")
    except FileNotFoundError:
        print("File not found. Please provide correct file paths.")
    except crypto.X509StoreContextError as e:
        print("Certificate verification failed:", e)

def verify_signature(signature, message, sender_certificate_path):
    try:
        # Load Alice's certificate
        with open(sender_certificate_path, 'rb') as f:
            sender_certificate_data = f.read()

        sender_certificate = crypto.load_certificate(crypto.FILETYPE_PEM, sender_certificate_data)
        sender_public_key = sender_certificate.get_pubkey()

        # Verify the digital signature using Alice's public key
        crypto.verify(sender_public_key, signature, message, 'sha256')
        print("Digital signature verification successful!")
    except FileNotFoundError:
        print("File not found. Please provide correct file paths.")
    except crypto.Error as e:
        print("Digital signature verification failed:", e)

# Example usage
if __name__ == "__main__":
    cms_file_path = 'alice_message.cms'
    bank_certificate_path = 'bank_certificate.pem'

     with open('alice_message.cms', 'rb') as f:
        cms_data = SignedData.load(f.read())

    # Extract encrypted message and signature from the CMS file
    # (Assuming you have a method to extract components from the CMS)
    encrypted_message = cms_data.data
    signature = cms_data.signers[0].signature
    sender_certificate_path = 'alice_certificate.pem'

    verify_certificate(sender_certificate_path, bank_certificate_path)
    verify_signature(signature, encrypted_message, sender_certificate_path)
```

### Example 3: Decryption and Reading by Bob

Bob successfully verifies Alice's certificate and the digital signature, proceeds to decrypt the message, and reads it.

```python
# Python code for decryption and reading by Bob
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.serialization import load_pem_private_key
from cryptography.hazmat.primitives.asymmetric import padding

def decrypt_message(encrypted_message, recipient_private_key_path):
    try:
        # Load Bob's private key
        with open(recipient_private_key_path, 'rb') as f:
            recipient_private_key_data = f.read()
        
        recipient_private_key = serialization.load_pem_private_key(recipient_private_key_data, password=None, backend=default_backend())

        # Decrypt the message using Bob's private key
        decrypted_message = recipient_private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=padding._MGF1_HASH_ALGORITHMS[hashes.SHA256]),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

        return decrypted_message.decode('utf-8')
    except FileNotFoundError:
        print("File not found. Please provide correct file paths.")

# Example usage
if __name__ == "__main__":
    encrypted_message = b"SOME_ENCRYPTED_MESSAGE_HERE"
    recipient_private_key_path = 'bob_private_key.pem'

    decrypted_message = decrypt_message(encrypted_message, recipient_private_key_path)
    print("Decrypted message:", decrypted_message)

```

## Conclusion

In this article, we've explored the essential components of secure information sharing using private/public keys and trusted certificates. By generating key pairs, creating trusted certificates, and employing cryptographic techniques such as digital signature verification and encryption, individuals and organizations can establish secure channels for communication. Understanding these concepts and their practical applications is crucial in today's digital landscape, where privacy and security are of utmost importance.

from cryptography import x509
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from datetime import datetime, timedelta

def create_certificate(subject_name, issuer_certificate_path, issuer_private_key_path, file_path):
    # Load issuer certificate and private key
    with open(issuer_certificate_path, 'rb') as f:
        issuer_cert = x509.load_pem_x509_certificate(f.read(), default_backend())
    
    with open(issuer_private_key_path, 'rb') as f:
        issuer_key = serialization.load_pem_private_key(f.read(), password=None, backend=default_backend())

    # Create a new key pair for the certificate
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )

    # Create the certificate
    builder = (
        x509.CertificateBuilder()
        .subject_name(x509.Name([x509.NameAttribute(x509.NameOID.COMMON_NAME, subject_name)]))
        .issuer_name(issuer_cert.subject)
        .public_key(private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.utcnow())
        .not_valid_after(datetime.utcnow() + timedelta(days=3650))  # Valid for 10 years
    )

    # Sign the certificate with the issuer's private key
    certificate = builder.sign(issuer_key, hashes.SHA256(), default_backend())

    # Save the certificate to a file
    with open(file_path, 'wb') as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))

# Example usage
create_certificate('Alice', 'bank_certificate.pem', 'bank_private_key.pem', 'alice_certificate.pem')
create_certificate('Bob', 'bank_certificate.pem', 'bank_private_key.pem', 'bob_certificate.pem')

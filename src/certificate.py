from cryptography import x509
from cryptography.x509 import load_pem_x509_certificate
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from cryptography.x509.oid import NameOID
from datetime import datetime, timedelta
import RSA_algorithm
from cryptography.hazmat.backends import default_backend
from cryptography import x509
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import hashes
from cryptography.x509.oid import NameOID
import datetime

def load_ca_public_key(filename):
    with open("keys/"+filename, "rb") as f:
        ca_public_key_data = f.read()
        ca_public_key = serialization.load_pem_public_key(ca_public_key_data)
        print(ca_public_key)
        return ca_public_key
# Load the CA's public key from a file (assuming you have it)


def create_certificate(public_key):
    ca_public_key=load_ca_public_key("ca_public_key.pem")
# Define the subject information for your certificate
    subject = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, u"ZA"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, u"CAPE TOWN"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, u"UCT"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, u"Computer Science Honours"),
        x509.NameAttribute(NameOID.COMMON_NAME, u"NIS"),
    ])

    certificate_ca=load_certificate("ca_certificate.pem")
    # Build your certificate
    cert = x509.CertificateBuilder().subject_name(subject)
    cert = cert.issuer_name(certificate_ca.subject)  # Issuer is the CA
    cert = cert.public_key(pub)
    cert = cert.serial_number(x509.random_serial_number())
    cert = cert.not_valid_before(datetime.datetime.utcnow())
    cert = cert.not_valid_after(datetime.datetime.utcnow() + timedelta(days=365))  # Valid for 1 year
    cert = cert.add_extension(x509.SubjectAlternativeName([x509.DNSName(u"UCT.com")]),
        critical=False,
    )
# Sign your certificate with the CA's public key (not possible in reality)
# For this example, we'll assume you have the CA's private key as well
    with open("keys/"+"ca_private_key.pem", "rb") as f:
        ca_private_key_data = f.read()
        ca_private_key = serialization.load_pem_private_key(ca_private_key_data, password=None)
    cert = cert.sign(ca_private_key, hashes.SHA256())
    save_certificate(cert)
    print("hello")
    return cert
# Save your certificate to a file

def save_certificate(certificate):
     with open("keys/"+"your_cert.pem", "wb") as f:
        f.write(certificate.public_bytes(serialization.Encoding.PEM))


def verify_certificate():
# Load the CA's public key from a file (assuming you have it)
    print( "yo")
    with open("keys/"+ "ca_public_key.pem", "rb") as f:
        ca_public_key_data = f.read()
        ca_public_key = serialization.load_pem_public_key(ca_public_key_data)

    # Load the certificate to be verified from a file
   

    with open("keys/"+ "your_cert.pem", "rb") as f:
        cert_data = f.read()
        cert = load_pem_x509_certificate(cert_data)

    # Verify the certificate
    try:
        ca_public_key.verify(
            cert.signature,
            cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            cert.signature_hash_algorithm,
        )
        print("Certificate is valid and has been verified.")
        return (cert.public_key(), True)
    except Exception as e:
        print("Certificate verification failed:", str(e))
        return ("Error", False)

def load_certificate(filename):  
    
    try:
        with open("keys/"+filename, "rb") as f:
            cert_data = f.read()
            cert = load_pem_x509_certificate(cert_data)
            return cert

    except Exception as e:
        print("Certificate verification failed:", str(e))
        return ("Error", False)



def create_ca_certificate():
    # Generate a key pair for the CA
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    public_key=private_key.public_key()

    # Create a self-signed certificate for the CA
    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COUNTRY_NAME, "US"),
        x509.NameAttribute(NameOID.STATE_OR_PROVINCE_NAME, "California"),
        x509.NameAttribute(NameOID.LOCALITY_NAME, "San Francisco"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "My CA"),
        x509.NameAttribute(NameOID.COMMON_NAME, "My CA"),
    ])

    ca_certificate = x509.CertificateBuilder().subject_name(
        subject
    ).issuer_name(
        issuer
    ).public_key(
        private_key.public_key()
    ).serial_number(
        x509.random_serial_number()
    ).not_valid_before(
        datetime.datetime.utcnow()
    ).not_valid_after(
        # Our CA is valid for 10 years
        datetime.datetime.utcnow() + datetime.timedelta(days=3650)
    ).sign(
        private_key, hashes.SHA256(), default_backend()
    )

    # Serialize the private key and the certificate
    private_key_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )

    public_key_pem=public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    ca_certificate_pem = ca_certificate.public_bytes(
        encoding=serialization.Encoding.PEM,
    )

    # Save the private key and the certificate to files
    with open("keys/"+"ca_private_key.pem", "wb") as f:
        f.write(private_key_pem)

    with open("keys/"+"ca_public_key.pem", "wb") as f:
        f.write(public_key_pem)


    with open("keys/"+"ca_certificate.pem", "wb") as f:
        f.write(ca_certificate_pem)

# Call the method to create the CA certificate
# create_ca_certificate()
def gen_private_key():
    """
    :return:
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    return private_key

# Generate Public Key
def gen_public_key(private_key):
    """
    :param private_key:
    :return:
    """
    public_key = private_key.public_key()
    return public_key

pri=gen_private_key()
pub=gen_public_key(pri)
#create_ca_certificate()
create_certificate(pub) # Create a certificate
verify_certificate()
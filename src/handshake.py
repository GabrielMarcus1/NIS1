import os
import socket
from certificate_utils import verify_certificate
import security_utils

def send_certifiicate_and_nonce(certificate):
    """
    Send the certificate and nonce to the client.
    """
    # Get the certificate and nonce
    nonce = os.urandom(16)
    return (certificate, nonce)
   


def recieve_certifiicate_and_nonce(handshake_obj):
    """
   
    """
    # Get the certificate and nonce
    certificate = handshake_obj.certificate
    nonce = handshake_obj.nonce
    friends_certificate = certificate.verify_certificate()
    if(friends_certificate[1] ==True):
        friends_public_key= friends_certificate[0]
        my_certificate= certificate.load_certificate("your_cert.pem")
        return(my_certificate, nonce)
        
def perform_handshake(sock, own_cert_path, own_private_key_path, remote_ca_cert_path):
    # Load own private key
    own_private_key = security_utils.load_key(own_private_key_path, "private")
    
    # Load and send own certificate
    with open(own_cert_path, "rb") as cert_file:
        own_cert = cert_file.read()
        sock.sendall(own_cert)
        print("Sent own certificate to the remote party.")

    # Receive remote party's certificate
    remote_cert = sock.recv(2048)  # Adjust buffer size as necessary
    with open("remote_cert_received.pem", "wb") as temp_file:
        temp_file.write(remote_cert)
    print("Received remote party's certificate.")

    # Verify the remote party's certificate
    remote_public_key = verify_certificate("remote_cert_received.pem", remote_ca_cert_path)
    if remote_public_key is None:
        raise Exception("Failed to verify remote party's certificate.")
    else:
        print("Remote party's certificate verified successfully.")

    # Optionally, return the remote public key for further communication use
    return remote_public_key

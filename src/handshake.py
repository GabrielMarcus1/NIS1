import os


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
        
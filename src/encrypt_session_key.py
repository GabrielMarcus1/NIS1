# Creates a new message with encrypted PUb + Ks and Ks, X
import json

from RSA_algorithm import aes_encrypt_message, rsa_encrypt

# generates message with encrpted secret key and encrypted message
def generate_confidentiality(secret_key, message, public_key):

    #encryptes data using secret key
    aes_encryption = aes_encrypt_message(message, secret_key)

    # encryptes secret key using rsa
    rsa_encryption = rsa_encrypt(secret_key, public_key)

    data = {
        "session_key": rsa_encryption,
        "encrypted_file": aes_encryption
    }

    return data

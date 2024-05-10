import secrets
import cryptography
from cryptography.hazmat.primitives.asymmetric import rsa # type: ignore
from cryptography.hazmat.primitives.asymmetric import padding # type: ignore
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import hashlib
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os


############KEY GENERATION####################
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
#############ENCRYPTION AND DECRYPTION (PRIVATE & PUBLIC KEYS)####################
# encrypte message using other users private key
def encrypt(message, public_key):
    """
    :param message:
    :param public_key:
    :return: Cipher text
    """
    message = message.encode("utf-8")
    cipher = public_key.encrypt( message,padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return cipher

# Decrypt message using private key
def decrypt(cipher, private_key):
    """
    This function takes cipher (to be decoded after decryption) and generated private key as input and returns the
    plaintext.
    Returns: plaintext
    """
    plaintext = private_key.decrypt(
        cipher,
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )

    return plaintext.decode("utf8")
###################################################################

#################SECRET KEY#########################################
def generate_secret_key():
    # Generate a random 32-byte (256-bit) key
    return os.urandom(32)

def encrypt_message(message, secret_key):
    # Generate a random IV (Initialization Vector)
    iv = os.urandom(16)
    
    # make the message paramter into byte form
    message_bytes = message.encode("utf-8")
    # Create an AES cipher with CBC mode using the secret key and IV
    cipher = Cipher(algorithms.AES(secret_key), modes.CBC(iv), backend=default_backend())
    # Encrypt the message
    encryptor = cipher.encryptor()
    #print(encryptor.update(message))
    ciphertext = encryptor.update(message_bytes) + encryptor.finalize()
    # Return the IV and ciphertext
    return iv + ciphertext

def decrypt_message(encrypted_message, secret_key):
    # Extract the IV from the encrypted message
    iv = encrypted_message[:16]

    ciphertext = encrypted_message[16:]

    # Create an AES cipher with CBC mode using the secret key and IV
    cipher = Cipher(algorithms.AES(secret_key), modes.CBC(iv), backend=default_backend())

    # Decrypt the ciphertext
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()
    print(decrypted_message)
    return decrypted_message

######################################################################


######################################################################

############KEY MANAGEMENT#######################
# Save Key to file. Key is in PEM format
def save_key(key, filename, key_type):
    """
    Save key to file
    """
    with open("../keys/"+filename, "wb") as f:
        if key_type == "private":
            f.write(key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption()
            ))
        elif key_type == "public":
            f.write(key.public_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PublicFormat.SubjectPublicKeyInfo
            ))
        else:
            raise ValueError("Invalid key type. Must be 'private' or 'public'.")

#Load key from PEM file 
def load_key(filename, key_type):
    """
    Load key from PEM file
    """
    with open("../keys/"+filename, "rb") as f:
        key_pem = f.read()
        if key_type == "private":
            key = serialization.load_pem_private_key(
                key_pem,
                password=None,  # No password protection
                backend=default_backend()
            )
        elif key_type == "public":
            key = serialization.load_pem_public_key(
                key_pem,
                backend=default_backend()
            )
        else:
            raise ValueError("Invalid key type. Must be 'private' or 'public'.")
    return key
#################################################



############HASHING##############################
def hash(message):
    """
    This function takes a message as input and returns the hexadecimal digest of the SHA-256 hash of the message.
    Parameters:
    message (str): The message to be hashed.

    Returns:
    str: The hexadecimal digest of the SHA-256 hash of the message.
    """
    sha256_hash = hashlib.sha256()
    sha256_hash.update(message)
    # Get the hexadecimal digest of the hash
    hex_digest = sha256_hash.hexdigest()
    # digest = sha256_hash.digest() 
    # ^^^^This is smaller than hexdigest, its half thwe size and should be used once we are done debugging
    return hex_digest

def verify_hash(message, hex_digest):
    """
    This function takes a message and a hexadecimal digest as input and returns True if the hexadecimal digest is the SHA-256 hash of the message, and False otherwise.
    Parameters:
    message (str): The message to be hashed.
    hex_digest (str): The hexadecimal digest to be verified.

    Returns:
    bool: True if the hexadecimal digest is the SHA-256 hash of the message, and False otherwise.
    """
    return hash(message) == hex_digest  # Compare the hash of the message with the given hexadecimal digest
##################################


def generate_shared_key():

    # Generate a random 256-bit (32-byte) shared key
    shared_key = secrets.token_bytes(32)
    return shared_key



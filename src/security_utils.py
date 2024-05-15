import json
import secrets
import cryptography
from cryptography.hazmat.primitives.asymmetric import rsa # type: ignore
from cryptography.hazmat.primitives.asymmetric import padding # type: ignore
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
import hashlib
from cryptography.hazmat.primitives.padding import PKCS7
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os



############# KEY GENERATION,ENCRYPTION AND DECRYPTION (PRIVATE & PUBLIC KEYS)####################
# note the keys generated are once off and are stored in the respsective users keys files but for testing we can just use this 
def gen_private_key():
    """
    :return:
    """
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
    )
    return private_key

def gen_public_key(private_key):
    """
    :param private_key:
    :return:
    """
    public_key = private_key.public_key()
    return public_key

# encrypte message using other users private key
def rsa_encrypt(message, public_key):
    """
    :param message:
    :param public_key:
    :return: Cipher text
    """
    # message = message.encode("utf-8")
    cipher = public_key.encrypt( message,padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return cipher

def rsa_decrypt(cipher, private_key):
    """
    This function takes cipher (to be decoded after decryption) and generated private key as input and returns the
    plaintext.
    Returns: plaintext
    """
    try:

        plaintext = private_key.decrypt(
            cipher,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
    except:
        print("Error decrypting the message")
        plaintext="error incorrect key used in decrypting message"
    return plaintext


    
###################################################################

#################SECRET KEY Generation, Decryption Encryption#########################################
def generate_secret_key():
    # Generate a random 32-byte (256-bit) key
    return os.urandom(32)

def aes_encrypt_message(message, secret_key):
    """
    Encrypts the message using AES-CBC mode.
    Parameters:
    message (bytes): The message to be encrypted.
    secret_key (bytes): The secret key used for encryption.
    Returns:
    bytes: The IV and ciphertext.
    """
    # Generate a random IV (Initialization Vector)
    iv = os.urandom(16)

    # Create an AES cipher with CBC mode using the secret key and IV
    cipher = Cipher(algorithms.AES(secret_key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()

    # Apply PKCS7 padding to ensure message length is a multiple of the block size
    padder = PKCS7(algorithms.AES.block_size).padder()
    padded_message = padder.update(message) + padder.finalize()

    # Encrypt the padded message
    ciphertext = encryptor.update(padded_message) + encryptor.finalize()

    # Return the IV and ciphertext
    return iv + ciphertext


def aes_decrypt_message(encrypted_message, secret_key):
    """
    This function takes an encrypted message and a secret key as input and decrypts the message using AES-CBC mode.
    Parameters:
    encrypted_message (bytes): The encrypted message to be decrypted.
    secret_key (bytes): The secret key used for decryption.

    Returns:
    bytes: The decrypted message.
    """
    # Extract the IV from the encrypted message
    iv = encrypted_message[:16]
    ciphertext = encrypted_message[16:]

    # Create an AES cipher with CBC mode using the secret key and IV
    cipher = Cipher(algorithms.AES(secret_key), modes.CBC(iv), backend=default_backend())
    
    # Decrypt the ciphertext
    decryptor = cipher.decryptor()
    decrypted_message = decryptor.update(ciphertext) + decryptor.finalize()
    print("The cipher is: ",decrypted_message)
    return decrypted_message

######################################################################


######################################################################

############KEY MANAGEMENT#######################
# Save Key to file. Key is in PEM format
def save_key(key, filename, key_type):
    """
    Save key to file
    """
    with open("keys/"+filename, "wb") as f:
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


#################################################


############HASHING########################
# def hash(message):
#     """
#     This function takes a message as input and returns the hexadecimal digest of the SHA-256 hash of the message.
#     Parameters:
#     message (str): The message to be hashed.

#     Returns:
#     str: The hexadecimal digest of the SHA-256 hash of the message.
#     """
#     sha256_hash = hashlib.sha256()
#     sha256_hash.update(message)
#     # Get the hexadecimal digest of the hash
#     hex_digest = sha256_hash.hexdigest()
#     # digest = sha256_hash.digest() 
#     # ^^^^This is smaller than hexdigest, its half thwe size and should be used once we are done debugging
#     return hex_digest

# def verify_hash(message, hex_digest):
#     """
#     This function takes a message and a hexadecimal digest as input and returns True if the hexadecimal digest is the SHA-256 hash of the message, and False otherwise.
#     Parameters:
#     message (str): The message to be hashed.
#     hex_digest (str): The hexadecimal digest to be verified.

#     Returns:
#     bool: True if the hexadecimal digest is the SHA-256 hash of the message, and False otherwise.
#     """
#     return hash(message) == hex_digest  # Compare the hash of the message with the given hexadecimal digest

def hash_message(message):
    """
    This function takes a message as input and returns the hexadecimal digest of the SHA-256 hash of the message.
    Parameters:
    message (str): The message to be hashed.

    Returns:
    str: The hexadecimal digest of the SHA-256 hash of the message.
    """

    # Encoding message object
    message_json = json.dumps(message, sort_keys=True).encode('utf-8')

    sha256_hash = hashlib.sha256()
    sha256_hash.update(message_json)

    # Get the hexadecimal digest of the hash
    hex_digest = sha256_hash.hexdigest()
    # digest = sha256_hash.digest() 
    # ^^^^This is smaller than hexdigest, its half the size and should be used once we are done debugging
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


# creates message with hex digest
def generate_hash_message(message):
    message_json = json.dumps(message)
    hex_digest = hash(message_json)

    message = {
        "message-digest": hex_digest,
    }

    return message

def load_key(key_path, key_type):
    with open("keys/"+key_path, "rb") as key_file:
        key_data = key_file.read()
        if key_type == "private":
            return serialization.load_pem_private_key(key_data, password=None, backend=default_backend())
        elif key_type == "public":
            return serialization.load_pem_public_key(key_data, backend=default_backend())
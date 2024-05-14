# Generates the message signature

import hashlib
from datetime import datetime
from cryptography.hazmat.primitives import serialization
from security_utils import aes_decrypt_message, generate_hash_message, rsa_decrypt
import os
from datetime import datetime
import tkinter as tk
from tkinter import filedialog
import base64
import json
import zlib
import json
from security_utils import aes_encrypt_message, rsa_encrypt
import json
def generate_key_id (public_key):
    fingerprint = generate_fingerprint(public_key)
    # Extract the Key ID (last 8 bytes of the fingerprint)
    key_id = fingerprint[-8:].hex()  # Take the last 8 bytes and convert to hexadecimal
    return key_id

# generate key fingerprint of publickey used in Key ID
def generate_fingerprint(public_key):
    public_key_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    sha256_hash = hashlib.sha256(public_key_bytes)
    fingerprint = sha256_hash.digest()
    return fingerprint

# generating message signature
def generate_signature(public_key, message):
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    key_id = generate_key_id(public_key)
    digest = generate_hash_message(message)
    signature = {
        "Timestamp": timestamp,
        "Key_ID": key_id,
        "Digest": digest  # Include the hash digest in the signature
    }
    return signature


def create_message_data():
    print("Select an image")
    root = tk.Tk()
    root.withdraw()

    image = filedialog.askopenfilename(filetypes=[("Image files", "*.jpg;*.jpeg;*.png")])

    caption = input("Enter a Caption:\n")

    filename = os.path.basename(image)
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    with open(image, "rb") as image:
        data = image.read()

    # Base64 encode the image data
    data_b64 = base64.b64encode(data).decode('utf-8')

    metadata = {
        "Caption": caption,
        "Image": data_b64
    }

    message = {
        "Filename": filename,
        "Timestamp": timestamp,
        "Data": metadata
    }
    return message


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


def compress_signature_and_message(signature, message):
    """
    Compresses the combined signature and message using zlib compression algorithm.
    """

    # Serialize dictionaries to JSON strings and encode as bytes
    signature_bytes = json.dumps(signature)
    message_bytes = json.dumps(message)

    # Concatenate signature and message bytes with a separator
    combined_data = (signature_bytes + "|" + message_bytes).encode("utf-8")

    # Compress the combined data
    compressed_data = zlib.compress(combined_data)
    return compressed_data

def decompress_signature_and_message(compressed_data):
    """
    Decompresses the compressed signature and message data.
    Parameters:
    compressed_data (bytes): The compressed data to be decompressed.
    Returns:
    tuple: A tuple containing the original signature and message.
    """
    # Decompress the compressed data
    combined_data = zlib.decompress(compressed_data)

    # Split the combined data into signature and message bytes
    separator_index = combined_data.index(b"|")
    signature_bytes = combined_data[:separator_index]
    message_bytes = combined_data[separator_index + 1:]

    # Decode the signature and message bytes from JSON strings
    signature = json.loads(signature_bytes.decode('utf-8'))
    message = json.loads(message_bytes.decode('utf-8'))

    decompressed = {
        "signature": signature,
        "message": message
    }

    # Return the original signature and message
    return decompressed


# Creates a new message with encrypted PUb + Ks and Ks, X


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


def decrypt_message_PGP(message, private_key):
    session_key = (message["session_key"])
    
    decrypted_session_key = rsa_decrypt(session_key, private_key)
    encrypted_file = (message["encrypted_file"])
   
    decrypted_file= aes_decrypt_message(encrypted_file, decrypted_session_key)

    # print(decrypted_file)
    file= decompress_signature_and_message(decrypted_file)
   
    signature= file['signature']
    digest = signature['Digest']
    
    message=(file["signature"])
    print(message)
    
    message = file["message"]

    # print(message)
    message = json.dumps(message)
    message_json = json.dumps(message, sort_keys=True).encode('utf-8')
    sha256_hash = hashlib.sha256()
    sha256_hash.update(message_json)

    # Get the hexadecimal digest of the hash
    hex_digest = sha256_hash.hexdigest()
    # message=message.decode()	
   
    print(hex_digest)
    



def create_text():
    print("Select an image")
    root = tk.Tk()
    root.withdraw()

    image = filedialog.askopenfilename(filetypes=[("Image files", "*.jpg;*.jpeg;*.png")])

    caption = input("Enter a Caption:\n")

    filename = os.path.basename(image)
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    with open(image, "rb") as image:
        data = image.read()

    # Base64 encode the image data
    data_b64 = base64.b64encode(data).decode('utf-8')

    metadata = {
        "Caption": caption,
        "Image": data_b64
    }

    message = {
        "Filename": filename,
        "Timestamp": timestamp,
        "Data": metadata
    }
    return message



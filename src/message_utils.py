# Generates the message signature

import hashlib
from datetime import datetime
from cryptography.hazmat.primitives import serialization
from security_utils import aes_decrypt_message, generate_hash_message, hash_message, rsa_decrypt, verify_hash
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

from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
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
# generates Signed Data
def generate_signature(private_key, message, public_key):
        timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        key_id = generate_key_id(public_key)
        print("The message being sent which must be verified on recivers side with the hash is: ", message)
        # hash_message is just the hash method in security.utils -> changed cause "hash" is a reserved word
        digest = hash_message(message).encode("utf8")


        # Message Digest Signed
        signature = private_key.sign(
            digest,
            padding.PKCS1v15(),
            hashes.SHA256()
        )


        signed_data = {
            "Timestamp": timestamp,
            "Key_ID": key_id,
            "Digest": digest.hex(),
            "Signature": signature.hex()

        }
        print("Generated the signature ")
        return signed_data

def verify_signature(public_key, digest, signature):
    # converts from Hex to bytes
    signature = bytes.fromhex(signature)

    # converts the digest to bytes
    digest = bytes.fromhex(digest)

    try:
        public_key.verify(
            signature,
            digest,
            padding.PKCS1v15(),
            hashes.SHA256()
        )
        return True  # Signature is valid
    except Exception as e:
        print(f"Signature verification failed: {e}")
        return False  # Signature is invalid

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
    print("Compressed signature + method ")
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
    print("Decompressed signature and message")
    return decompressed


# Creates a new message with encrypted PUb + Ks and Ks, X

def create_header(message_length):
    return message_length.to_bytes(4, byteorder='big')

# generates message with encrpted secret key and encrypted message
def generate_confidentiality(secret_key, message, public_key):

    #encryptes data using secret key
    aes_encryption = aes_encrypt_message(message, secret_key)

    # encryptes secret key using rsa
    rsa_encryption = rsa_encrypt(secret_key, public_key)

    # data = {
    #     "session_key": rsa_encryption,
    #     "encrypted_file": aes_encryption
    # }
    header= len(rsa_encryption).to_bytes(4, byteorder='big')
    data =header+ rsa_encryption+ aes_encryption
    print("Generated Full object to be sent \n")
    return data


def decrypt_message_PGP_image(message, private_key):
    header = message[:4]
    message_length = int.from_bytes(header, byteorder='big')
    print("message length: ",message_length)
    encrypted_message = message[4:4+message_length]
    # print("Encrypted Session Key: ", encrypted_message)
    
    decrypted_session_key = rsa_decrypt(encrypted_message, private_key)
    # print("Decrypted Session Key: ", decrypted_session_key)
    encrypted_file_start=4+ message_length
    encrypted_message = message[encrypted_file_start:]
    decrypted_message= aes_decrypt_message(encrypted_message, decrypted_session_key)
    # print("Decrypted message: ",  decrypted_message)
    file= decompress_signature_and_message(decrypted_message)
    print(file)
    signature= file['signature']
    digest = signature['Digest']
    message = file["message"]

    verify_digest = verify_hash(message, digest)
    
    if verify_digest == True:
        print("The message has been verified and the hash is correct")
    else:
        print("The message has not been verified and the hash is incorrect. Message may have been tampered with")
    
    json_data= (json.loads(message)) # json of the acrtual message we wanted to send
    caption= json_data['Data']['Caption']
    image= json_data['Data']['Image']

    return (image)
    # print(hex_digest)


def decrypt_message_PGP(message, private_key):
    header = message[:4]
    message_length = int.from_bytes(header, byteorder='big')
    print("message length:",message_length)
    encrypted_message = message[4:4+message_length]
    # print("Encrypted Session Key: ", encrypted_message)
    
    decrypted_session_key = rsa_decrypt(encrypted_message, private_key)
    # print("Decrypted Session Key: ", decrypted_session_key)
    encrypted_file_start=4+ message_length
    encrypted_message = message[encrypted_file_start:]
    decrypted_message= aes_decrypt_message(encrypted_message, decrypted_session_key)
    # print("Decrypted message: ",  decrypted_message)
    file= decompress_signature_and_message(decrypted_message)

    signature= file['signature']
    digest = signature['Digest']

    message = file["message"]
    print(message)
    json_data= (json.loads(message)) # json of the acrtual message we wanted to send
    message_data= json_data['Data']
   
    print("Decrypted Data and retrieved the message that was sent \n")
    return (json.dumps(message_data))
    # print(hex_digest)
    



def create_string(message):
    data_b64 =  message

    metadata = {
        "Caption": "TEXT MESSAGE",
        "Image": data_b64
    }
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    message = {
         "Filename": "MESSAGE",
         "Timestamp": timestamp,
        "Data": metadata
    }
    return message

# def create_string(message):   
#     timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')
#     message = {
#          "Filename": "MESSAGE",
#          "Timestamp": timestamp,
#         "Data": message
#     }
#     return message


def create_image_message(message, caption):
    
    fileName = os.path.basename(fileName)
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    data_b64 = message # message was already base64 encoded

    metadata = {
        "Caption": "PLEASE SUPPLY A CAPTION",
        "Image": data_b64
    }

    message = {
        "Filename": "fileName",
        "Timestamp": timestamp,
        "Data": metadata
    }
    return message


def save_file(image_data):
         file_path = filedialog.asksaveasfilename(defaultextension=".jpg", filetypes=[("JPEG files", "*.jpg"), ("All files", "*.*")])
         if file_path: 
            with open("keys/file.png", "wb") as file:
                file.write(image_data)
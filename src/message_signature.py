# Generates the message signature

import hashlib
from datetime import datetime

from cryptography.hazmat.primitives import serialization

from security import generate_hash_message

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








# Generates the message signature

import hashlib
from datetime import datetime
from security import generate_hash_message

def generate_key_id (public_key):
    fingerprint = generate_fingerprint(public_key)
    # Extract the Key ID (last 8 bytes of the fingerprint)
    key_id = fingerprint[-16:]  # Take the last 16 characters (8 bytes)

    return key_id

# generate key fingerprint of publickey used in Key ID
def generate_fingerprint(public_key):

    sha256_hash = hashlib.sha256()
    sha256_hash.update(public_key)
    fingerprint = sha256_hash

    return fingerprint

# generating message signature
def generate_signature(public_key, message):

    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    signature = generate_key_id(public_key)

    digest = generate_hash_message(message).get("message-digest")

    signature = {
        "Timestamp": timestamp,
        "Signature": signature,
        "Digest": digest
    }

    return signature








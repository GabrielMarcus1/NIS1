import hashlib


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
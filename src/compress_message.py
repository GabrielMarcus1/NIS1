# Message compression

import zlib
import json

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

# compresses the signature and message
# compresses the signature and message
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





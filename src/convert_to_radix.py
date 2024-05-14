# converts file from and to radix64

import base64

# Encode encrypted data to Base64
def to_radix64(data):
    base64_encoded_data = base64.b64encode(data)

    return base64_encoded_data

def from_radix(encoded_data):
    data = base64.b64decode(encoded_data)

    return data


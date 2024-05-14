# method combining all of the security implementations to construct PGP message
import base64

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization

from text_generate import create_text
from message_signature import generate_signature
from RSA_algorithm import gen_public_key, gen_private_key, generate_secret_key, rsa_encrypt, rsa_decrypt
from compress_message import compress_signature_and_message
from encrypt_session_key import generate_confidentiality
from convert_to_radix import to_radix64, from_radix
import RSA_algorithm

private_key = gen_private_key()
public_key = gen_public_key(private_key)

# print(private_key)
# print(public_key)

# cipher takes plain text

# recipe for message
message =create_text()

secret = generate_secret_key()
#adds signature to message
signed = generate_signature(public_key,message)

compressed_file = compress_signature_and_message(signed, message)

# add confidentiality
confidential_file = generate_confidentiality(secret,compressed_file,public_key)

# print(confidential_file)
#print(secret)
RSA_algorithm.decrypt_message_PGP(confidential_file, private_key)

# radix_file = to_radix64()
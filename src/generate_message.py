# method combining all of the security implementations to construct PGP message
import base64
import json
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization
from security_utils import gen_public_key, gen_private_key, generate_secret_key
from message_utils import (
    compress_signature_and_message,
    create_string,
    generate_signature,
    generate_confidentiality,
)

# TODO:
# 1. Add key rings
# 2. Create secret key (Done) ✔️
# 3. Construct message (PGP  paradigm) (Done) ✔️
#       3.1 Authentication  (DONE) ✔️
#       3.2 Confidentiality (DONE) ✔️
# 4. Hashing (DONE) ✔️
# 5. Key management - key rings, private , public, other persons. secret...
# 6. Certificate (DONE) ✔️
# 7. Formatting message. (DONE) ✔️
# 8. Report
# 9. Testing and debugging
# 10. Refactor
# 11. Coments
# 12. Handshake to establish connections
# 13. Network setup (DONE) ✔️
# 14: GUI (DONE) ✔️
# 15. Add more security features
# 16. Make images send over network and save them
#########################TESTING ##########################################
# create a users public private key set
# private_key = gen_private_key()
# public_key = gen_public_key(private_key)

# private_key_bytes = private_key.private_bytes(
#     encoding=serialization.Encoding.PEM,
#     format=serialization.PrivateFormat.TraditionalOpenSSL,
#     encryption_algorithm=serialization.NoEncryption(),
# )

########################################################################################


def constuct_pgp_message(message, private_key,public_key):
    message = create_string(message)
    # print("The message is: ",message)
    messsages = json.dumps(message)
    # print("the next message is: ", messsages)
    secret = generate_secret_key()
    # adds signature to message
    signed = generate_signature(public_key, messsages)
    # print("The signed message is: ",signed)
    compressed_file = compress_signature_and_message(signed, messsages)
    # print("The compressed file is: ",compressed_file)
    confidential_file = generate_confidentiality(secret, compressed_file, public_key)
    # print("The confidential file is: ",confidential_file)

    return confidential_file


#
# fille= constuct_pgp_image("Hello World",private_key)

# print(confidential_file)
# print(secret)
# decrypt_message_PGP(fille, private_key)

####################################################################################


# ##########Testing 1########################
# # We are going to use the public and private keys in our key files
# private_key= RSA_algorithm.gen_private_key()
# public_key= RSA_algorithm.gen_public_key(private_key)
# RSA_algorithm.save_key(private_key, 'private_key.pem', 'private')
# RSA_algorithm.save_key(public_key, 'public_key.pem', 'public')

# # Read Keys from file
# pub_key= RSA_algorithm.load_key('public_key.pem', 'public')
# priv_key= RSA_algorithm.load_key('private_key.pem', 'private')

# #DCheck to see it works
# message= "Hello World"
# encrypted_message= RSA_algorithm.encrypt(message, pub_key)
# print("Encrypted messsage:  ",encrypted_message)
# decrypted_message= RSA_algorithm.decrypt(encrypted_message, priv_key)
# print("Decrypted messsage:  ",decrypted_message)

# #Generate a certificate for the key and then thats the certifcate the other user can use to get your public key.
# #Note we assume all users already have the public key of the Certifcate Authority who issueed our certificate

# #Get our public key fom our certificate
# #This shows that the other user can easily get our public key to authwenticate our messagte digest
# my_certificate=certificate.create_certificate(pub_key)
# pub_keys= certificate.verify_certificate()[0]
# if(pub_keys==pub_key):
#     print("Certificate verified")

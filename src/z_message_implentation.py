'''
This is where we will use the PGP algorithm
to construct the mesage as well as unravel the message
'''
from security_utils import *
from cryptography.hazmat.primitives import serialization
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
# 13. Network
# 14: GUI 




#########################TESTING ##########################################
#create a users public private key set
private_key = gen_private_key()
public_key = gen_public_key(private_key)

private_key_bytes = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    )
print(private_key_bytes)


# # cipher= RSA_algorithm.encrypt("Hello World",public_key)

# # decrypted= RSA_algorithm.decrypt(cipher,private_key)
# # print("Decrypted="+ decrypted )


# # cipher= RSA_algorithm.gen_secret_key()
# message = "Hello, world! This is a message to be encrypted."
# # print("Before encryption: "+ message)
# # encrypted=RSA_algorithm.encrypt_shared_key(message, cipher)

# # decrypt_shared_key= RSA_algorithm.decrypt_shared_key(encrypted, cipher)
# # print("decrypted message= "+ decrypt_shared_key)

# # ?Save the keys and reload it 
# # RSA_algorithm.save_key(private_key, 'private_key', 'private')
# # RSA_algorithm.save_key(public_key, 'public_key', 'public')

# # private= RSA_algorithm.load_key(private_key, 'private')
# # public= RSA_algorithm.load_key(public_key, 'public')
# secret_key = RSA_algorithm.generate_secret_key()
# encrypted_message = RSA_algorithm.encrypt_message(message, secret_key)
# decrypted_message = RSA_algorithm.decrypt_message(encrypted_message, secret_key)


################################################################################################

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



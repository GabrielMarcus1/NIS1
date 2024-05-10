'''
This is where we will use the PGP algorithm
to construct the mesage as well as unravel the message
'''
import RSA_algorithm

# TODO:  
# 1. Add key rings 
# 2. Create secret key (Done) ✔️
# 3. Construct message (PGP  paradigm)
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

        
#create a users public private key set
private_key = RSA_algorithm.gen_private_key()
public_key = RSA_algorithm.gen_public_key(private_key)

print(public_key)


# cipher= RSA_algorithm.encrypt("Hello World",public_key)

# decrypted= RSA_algorithm.decrypt(cipher,private_key)
# print("Decrypted="+ decrypted )


# cipher= RSA_algorithm.gen_secret_key()
message = "Hello, world! This is a message to be encrypted."
# print("Before encryption: "+ message)
# encrypted=RSA_algorithm.encrypt_shared_key(message, cipher)

# decrypt_shared_key= RSA_algorithm.decrypt_shared_key(encrypted, cipher)
# print("decrypted message= "+ decrypt_shared_key)

# ?Save the keys and reload it 
# RSA_algorithm.save_key(private_key, 'private_key', 'private')
# RSA_algorithm.save_key(public_key, 'public_key', 'public')

# private= RSA_algorithm.load_key(private_key, 'private')
# public= RSA_algorithm.load_key(public_key, 'public')
secret_key = RSA_algorithm.generate_secret_key()
encrypted_message = RSA_algorithm.encrypt_message(message, secret_key)
decrypted_message = RSA_algorithm.decrypt_message(encrypted_message, secret_key)
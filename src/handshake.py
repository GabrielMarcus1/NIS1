import socket
import rsa
from Crypto.Cipher import AES
from Crypto.Hash import SHA256
from Crypto import Random
import base64
import os

# Generate RSA key pairs for Alice and Bob
def generate_rsa_keys():
    (public_key, private_key) = rsa.newkeys(2048)
    return public_key, private_key

# Load the CA's public key (assumed to be pre-distributed)
def load_ca_public_key():
    with open("ca_public_key.pem", "rb") as f:
        ca_public_key = rsa.PublicKey.load_pkcs1(f.read())
    return ca_public_key

# Verify the received certificate
def verify_certificate(certificate, ca_public_key):
    try:
        rsa.verify(certificate, ca_public_key)
        return True
    except:
        return False

# Generate a shared secret key using Diffie-Hellman
def generate_shared_secret():
    secret = os.urandom(16)  # Replace with actual Diffie-Hellman key exchange
    return secret

# Encrypt a message using AES
def encrypt_message(message, key):
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padding = AES.block_size - len(message) % AES.block_size
    message += bytes([padding]) * padding
    encrypted_message = iv + cipher.encrypt(message)
    return base64.b64encode(encrypted_message).decode('utf-8')

# Decrypt a message using AES
def decrypt_message(encrypted_message, key):
    encrypted_message = base64.b64decode(encrypted_message)
    iv = encrypted_message[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_message = cipher.decrypt(encrypted_message[AES.block_size:])
    padding = decrypted_message[-1]
    return decrypted_message[:-padding].decode('utf-8')

# Alice and Bob's communication setup
def alice():
    # Generate RSA key pairs and load CA public key
    alice_public_key, alice_private_key = generate_rsa_keys()
    ca_public_key = load_ca_public_key()

    # Create a TCP socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('localhost', 65432))
        s.listen()
        print("Alice waiting for a connection...")
        conn, addr = s.accept()
        with conn:
            print('Connected by', addr)

            # Exchange certificates and verify
            conn.send(alice_public_key.save_pkcs1())
            bob_cert = conn.recv(1024)
            if verify_certificate(bob_cert, ca_public_key):
                print("Bob's certificate verified.")
            else:
                print("Certificate verification failed.")
                return

            # Generate and share secret key
            shared_secret = generate_shared_secret()
            encrypted_secret = rsa.encrypt(shared_secret, bob_cert)
            conn.send(encrypted_secret)

            # Communication loop
            while True:
                message = input("Enter message to send: ")
                encrypted_message = encrypt_message(message.encode('utf-8'), shared_secret)
                conn.send(encrypted_message.encode('utf-8'))

                encrypted_response = conn.recv(1024)
                response = decrypt_message(encrypted_response.decode('utf-8'), shared_secret)
                print("Bob:", response)

def bob():
    # Generate RSA key pairs and load CA public key
    bob_public_key, bob_private_key = generate_rsa_keys()
    ca_public_key = load_ca_public_key()

    # Create a TCP socket
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(('localhost', 65432))

        # Exchange certificates and verify
        alice_cert = s.recv(1024)
        if verify_certificate(alice_cert, ca_public_key):
            print("Alice's certificate verified.")
            s.send(bob_public_key.save_pkcs1())
        else:
            print("Certificate verification failed.")
            return

        # Receive and decrypt shared secret key
        encrypted_secret = s.recv(1024)
        shared_secret = rsa.decrypt(encrypted_secret, bob_private_key)

        # Communication loop
        while True:
            encrypted_message = s.recv(1024)
            message = decrypt_message(encrypted_message.decode('utf-8'), shared_secret)
            print("Alice:", message)

            response = input("Enter message to send: ")
            encrypted_response = encrypt_message(response.encode('utf-8'), shared_secret)
            s.send(encrypted_response.encode('utf-8'))

# Run Alice or Bob
if __name__ == "__main__":
    import sys
    if sys.argv[1] == 'alice':
        alice()
    elif sys.argv[1] == 'bob':
        bob()
    else:
        print("Usage: python handshake.py [alice|bob]")

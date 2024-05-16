import socket
import rsa
from Crypto.Cipher import AES
from Crypto import Random
import base64
import os

# Ensure keys and certificates exist
def ensure_keys_and_certificates(name):
    key_dir = "keys"
    cert_dir = "certs"
    os.makedirs(key_dir, exist_ok=True)
    os.makedirs(cert_dir, exist_ok=True)
    
    private_key_path = os.path.join(key_dir, f"{name}_private_key.pem")
    public_key_path = os.path.join(key_dir, f"{name}_public_key.pem")
    cert_path = os.path.join(cert_dir, f"{name}_cert.pem")

    if not os.path.exists(private_key_path):
        (public_key, private_key) = rsa.newkeys(2048)
        with open(private_key_path, "wb") as priv_file:
            priv_file.write(private_key.save_pkcs1())
        with open(public_key_path, "wb") as pub_file:
            pub_file.write(public_key.save_pkcs1())
        with open(cert_path, "wb") as cert_file:
            cert_file.write(public_key.save_pkcs1())  
        print(f"Keys and certificate for {name} generated and saved.")
    else:
        print(f"Keys and certificate for {name} already exist.")

def load_key(key_path):
    with open(key_path, "rb") as key_file:
        key = rsa.PublicKey.load_pkcs1(key_file.read()) if 'public' in key_path else rsa.PrivateKey.load_pkcs1(key_file.read())
    return key

def load_certificate(cert_path):
    with open(cert_path, "rb") as cert_file:
        cert = cert_file.read()
    return cert

def verify_certificate(cert, ca_public_key):
    try:
        rsa.verify(cert, ca_public_key)  # Simulated verification for demonstration
        return True
    except:
        return False

def generate_shared_secret():
    secret = os.urandom(16)
    return secret

def encrypt_message(message, key):
    iv = Random.new().read(AES.block_size)
    cipher = AES.new(key, AES.MODE_CBC, iv)
    padding = AES.block_size - len(message) % AES.block_size
    message += bytes([padding]) * padding
    encrypted_message = iv + cipher.encrypt(message)
    return base64.b64encode(encrypted_message).decode('utf-8')

def decrypt_message(encrypted_message, key):
    encrypted_message = base64.b64decode(encrypted_message)
    iv = encrypted_message[:AES.block_size]
    cipher = AES.new(key, AES.MODE_CBC, iv)
    decrypted_message = cipher.decrypt(encrypted_message[AES.block_size:])
    padding = decrypted_message[-1]
    return decrypted_message[:-padding].decode('utf-8')

def alice():
    ensure_keys_and_certificates("alice")
    alice_private_key = load_key("keys/alice_private_key.pem")
    alice_public_key = load_key("keys/alice_public_key.pem")
    ca_public_key = load_key("ca_public_key.pem")  # Assuming the CA public key is pre-distributed
    alice_cert = load_certificate("certs/alice_cert.pem")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(('localhost', 65432))
        s.listen()
        print("Alice waiting for a connection...")
        conn, addr = s.accept()
        with conn:
            print('Connected by', addr)

            conn.send(alice_cert)
            bob_cert = conn.recv(1024)
            if verify_certificate(bob_cert, ca_public_key):
                print("Bob's certificate verified.")
            else:
                print("Certificate verification failed.")
                return

            shared_secret = generate_shared_secret()
            encrypted_secret = rsa.encrypt(shared_secret, rsa.PublicKey.load_pkcs1(bob_cert))
            conn.send(encrypted_secret)

            while True:
                message = input("Enter message to send: ")
                encrypted_message = encrypt_message(message.encode('utf-8'), shared_secret)
                conn.send(encrypted_message.encode('utf-8'))

                encrypted_response = conn.recv(1024)
                response = decrypt_message(encrypted_response.decode('utf-8'), shared_secret)
                print("Bob:", response)

def bob():
    ensure_keys_and_certificates("bob")
    bob_private_key = load_key("keys/bob_private_key.pem")
    bob_public_key = load_key("keys/bob_public_key.pem")
    ca_public_key = load_key("ca_public_key.pem")
    bob_cert = load_certificate("certs/bob_cert.pem")

    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.connect(('localhost', 65432))

        alice_cert = s.recv(1024)
        if verify_certificate(alice_cert, ca_public_key):
            print("Alice's certificate verified.")
            s.send(bob_cert)
        else:
            print("Certificate verification failed.")
            return

        encrypted_secret = s.recv(1024)
        shared_secret = rsa.decrypt(encrypted_secret, bob_private_key)

        while True:
            encrypted_message = s.recv(1024)
            message = decrypt_message(encrypted_message.decode('utf-8'), shared_secret)
            print("Alice:", message)

            response = input("Enter message to send: ")
            encrypted_response = encrypt_message(response.encode('utf-8'), shared_secret)
            s.send(encrypted_response.encode('utf-8'))

if __name__ == "__main__":
    import sys
    if len(sys.argv) != 2 or sys.argv[1] not in ['alice', 'bob']:
        print("Usage in terminal: python handshake.py [alice|bob]")
        sys.exit(1)

    if sys.argv[1] == 'alice':
        alice()
    elif sys.argv[1] == 'bob':
        bob()

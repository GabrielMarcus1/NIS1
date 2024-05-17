import socket
import rsa

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

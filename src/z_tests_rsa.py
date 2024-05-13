import unittest
import os
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization
from RSA_algorithm import (gen_private_key, gen_public_key, encrypt, decrypt,
                           generate_secret_key, encrypt_message, decrypt_message,
                           save_key, load_key, hash, verify_hash)

class TestRSAAlgorithm(unittest.TestCase):

    def test_gen_private_key(self):
        private_key = gen_private_key()
        self.assertIsInstance(private_key, rsa.RSAPrivateKey)

    def test_gen_public_key(self):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = gen_public_key(private_key)
        self.assertIsInstance(public_key, rsa.RSAPublicKey)

    def test_encrypt_decrypt_rsa(self):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        plaintext = "Hello, world!"
        ciphertext = encrypt(plaintext, public_key)
        decrypted_plaintext = decrypt(ciphertext, private_key)

        self.assertEqual(plaintext, decrypted_plaintext)

    def test_gen_private_key(self):
        private_key = gen_private_key()
        self.assertIsInstance(private_key, rsa.RSAPrivateKey)

    def test_gen_public_key(self):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = gen_public_key(private_key)
        self.assertIsInstance(public_key, rsa.RSAPublicKey)

    def test_encrypt_decrypt_rsa(self):
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
        public_key = private_key.public_key()

        plaintext = "Hello, world!"
        ciphertext = encrypt(plaintext, public_key)
        decrypted_plaintext = decrypt(ciphertext, private_key)

        self.assertEqual(plaintext, decrypted_plaintext)

    def test_generate_secret_key(self):
        secret_key = generate_secret_key()
        self.assertIsInstance(secret_key, bytes)

    def test_encrypt_message(self):
        secret_key = generate_secret_key()
        message = "This is a secret message"
        encrypted_message = encrypt_message(message, secret_key)
        self.assertIsInstance(encrypted_message, bytes)

    def test_decrypt_message(self):
        secret_key = generate_secret_key()
        message = "This is a secret message"
        encrypted_message = encrypt_message(message, secret_key)
        decrypted_message = decrypt_message(encrypted_message, secret_key)
        self.assertEqual(message, decrypted_message)

    def test_save_key(self):
        private_key = gen_private_key()
        save_key(private_key, "private_key.pem", 'private')
        self.assertTrue(os.path.exists("keys/private_key.pem"))

    def test_load_key(self):
        private_key = gen_private_key()
        save_key(private_key, "private_key.pem", 'private')
        loaded_key = load_key("private_key.pem", 'private')
        # self.assertEqual(private_key, loaded_key)

    def test_hash(self):
        message = "This is a message"
        hashed_message = hash(message)
        self.assertIsInstance(hashed_message, bytes)

    def test_verify_hash(self):
        message = "This is a message"
        hashed_message = hash(message)
        self.assertTrue(verify_hash(message, hashed_message))
    

if __name__ == '__main__':
    unittest.main()

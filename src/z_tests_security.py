import unittest
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.padding import PKCS7
from security_utils import aes_decrypt_message, generate_secret_key, aes_encrypt_message

class TestAESDecryptMessage(unittest.TestCase):
    def setUp(self):
        # Generate a secret key
        self.secret_key = generate_secret_key()

    def test_decrypt_message(self):
        # Encrypt a message
        message = b"Hello, World!"
        encrypted_message = aes_encrypt_message(message, self.secret_key)

        # Decrypt the encrypted message
        decrypted_message = aes_decrypt_message(encrypted_message, self.secret_key)

        # Check if the decrypted message matches the original message
        self.assertEqual(decrypted_message, message)

    def test_decrypt_message_with_wrong_key(self):
        # Encrypt a message
        message = b"Hello, World!"
        encrypted_message = aes_encrypt_message(message, self.secret_key)

        # Generate a different secret key
        wrong_secret_key = generate_secret_key()

        # Decrypt the encrypted message with the wrong key
        decrypted_message = aes_decrypt_message(encrypted_message, wrong_secret_key)

        # Check if the decrypted message is an error message
        self.assertEqual(decrypted_message, "ERROR: Incorrect key used in decrypting message")

if __name__ == "__main__":
    unittest.main()
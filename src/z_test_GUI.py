import unittest
import os
import socket
from unittest.mock import patch
from security_utils import gen_private_key, save_key
from Client import GUIClient

class TestGUIClient(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        # Generate and save keys for testing
        cls.private_key_path = "test_private_key.pem"
        cls.public_key_path = "test_public_key.pem"
        private_key = gen_private_key()
        public_key = private_key.public_key()
        save_key(private_key, cls.private_key_path, "private")
        save_key(public_key, cls.public_key_path, "public")

    @patch('socket.socket.connect')
    def test_key_loading(self, mock_connect):
        """ Test if keys are loaded properly from files. """
        client = GUIClient(None, 'localhost', 12345, self.private_key_path, self.public_key_path)
        self.assertIsNotNone(client.client_private_key)
        self.assertIsNotNone(client.client_public_key)

    @patch('socket.socket.connect')
    def test_missing_key_files(self, mock_connect):
        """ Test the behavior when key files are missing. """
        with self.assertRaises(FileNotFoundError):
            GUIClient(None, 'localhost', 12345, "non_existent_private.pem", "non_existent_public.pem")

    @classmethod
    def tearDownClass(cls):
        # Clean up test key files
        if os.path.exists(cls.private_key_path):
            os.remove(cls.private_key_path)
        if os.path.exists(cls.public_key_path):
            os.remove(cls.public_key_path)

if __name__ == "__main__":
    unittest.main()

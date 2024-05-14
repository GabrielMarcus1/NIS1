import unittest
import os
import sys
from datetime import datetime, timedelta

from certificate import (load_ca_public_key, create_certificate, save_certificate,
                         verify_certificate, load_certificate, create_ca_certificate)

class TestCertificateFunctions(unittest.TestCase):

    def setUp(self):
        # Generate CA certificate for testing
        create_ca_certificate()

    def tearDown(self):
        # Clean up generated files after each test
        files_to_remove = ["ca_private_key.pem", "ca_public_key.pem", "ca_certificate.pem"]
        for file_name in files_to_remove:
            try:
                os.remove("keys/" + file_name)
            except FileNotFoundError:
                pass

    def test_load_ca_public_key(self):
        # Assuming the CA public key is generated during setUp()
        ca_public_key = load_ca_public_key("ca_public_key.pem")
        self.assertIsNotNone(ca_public_key)

    def test_create_certificate(self):
        # Assuming the CA certificate and keys are generated during setUp()
        ca_public_key = load_ca_public_key("ca_public_key.pem")
        cert = create_certificate(ca_public_key)
        self.assertIsNotNone(cert)

    def test_save_certificate(self):
        # Assuming the CA certificate is generated during setUp()
        ca_public_key = load_ca_public_key("ca_public_key.pem")
        cert = create_certificate(ca_public_key)
        save_certificate(cert)
        # Check if the certificate file is saved
        self.assertTrue(os.path.exists("keys/your_cert.pem"))

    def test_verify_certificate(self):
        # Assuming the CA certificate and keys are generated during setUp()
        ca_public_key = load_ca_public_key("ca_public_key.pem")
        cert = create_certificate(ca_public_key)
        save_certificate(cert)
        verified_key, verified = verify_certificate()
        self.assertTrue(verified)
        self.assertIsNotNone(verified_key)

    def test_load_certificate(self):
        # Assuming the CA certificate is generated during setUp() and saved during test_save_certificate()
        cert = load_certificate("your_cert.pem")
        self.assertIsNotNone(cert)


if __name__ == '__main__':
    unittest.main()

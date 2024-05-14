import socket
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, rsa
import base64

class Server:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.clients = []
        self.server_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.server_public_key = self.server_private_key.public_key()
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

    def start(self):
        self.socket.bind((self.host, self.port))
        self.socket.listen(5)
        print(f"Server listening on {self.host}:{self.port}")
        while True:
            client_socket, _ = self.socket.accept()
            print("Client connected")
            self.handle_client(client_socket)

    def handle_client(self, client_socket):
        try:
            while True:
                data_type = client_socket.recv(1024).decode()
                if data_type == 'TEXT':
                    self.handle_text(client_socket)
                elif data_type == 'IMAGE':
                    self.handle_image(client_socket)
        except Exception as e:
            print(f"Error: {e}")
        finally:
            client_socket.close()
            print("Client disconnected")

    def handle_text(self, client_socket):
        text_length = int(client_socket.recv(1024).decode())
        text_data = client_socket.recv(text_length).decode()
        print("Received text:", text_data)

    def handle_image(self, client_socket):
        file_length = int(client_socket.recv(1024).decode())
        image_data = b''
        while len(image_data) < file_length:
            packet = client_socket.recv(1024)
            if not packet:
                break
            image_data += packet
        image_data = base64.b64decode(image_data)
        with open('received_image.png', 'wb') as image_file:
            image_file.write(image_data)
        print("Image received and saved")

def main():
    server = Server("localhost", 12345)
    server.start()

if __name__ == "__main__":
    main()

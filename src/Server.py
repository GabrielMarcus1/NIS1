# import socket
# from cryptography.hazmat.backends import default_backend
# from cryptography.hazmat.primitives import serialization
# import base64
# from security_utils import gen_private_key

# class Server:
#     def __init__(self, host, port):
#         self.host = host
#         self.port = port
#         self.clients = []
#         self.server_private_key = gen_private_key()
#         self.server_public_key = self.server_private_key.public_key()
#         self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)

#     def start(self):
#         self.socket.bind((self.host, self.port))
#         self.socket.listen(5)
#         print(f"Server listening on {self.host}:{self.port}")
#         while True:
#             client_socket, _ = self.socket.accept()
#             print("Client connected")
#             self.handle_client(client_socket)


#     def handle_client(self, client_socket):
#         try:
#             while True:
#                 data_type = client_socket.recv(1024).decode()
#                 if data_type == 'TEXT':
#                     self.handle_text(client_socket)
#                 elif data_type == 'IMAGE':
#                     self.handle_image(client_socket)
#         except Exception as e:
#             print(f"Error: {e}")
#         finally:
#             client_socket.close()
#             print("Client disconnected")

#     def handle_text(self, client_socket):
#         text_length = int(client_socket.recv(1024).decode())
#         text_data = client_socket.recv(text_length).decode("utf-8")
#         print("Received text:", text_data)

#     def handle_image(self, client_socket):
#         file_length = int(client_socket.recv(1024).decode())
#         image_data = b''
#         while len(image_data) < file_length:
#             packet = client_socket.recv(1024)
#             if not packet:
#                 break
#             image_data += packet
#         image_data = base64.b64decode(image_data)
#         with open('received_image.png', 'wb') as image_file:
#             image_file.write(image_data)
#         print("Image received and saved")

# def main():
#     server = Server("localhost", 8000)
#     server.start()

# if __name__ == "__main__":
#     main()

import socket
import threading

class Server:
    def __init__(self, host, port):
        self.host = host
        self.port = port
        self.clients = []
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((self.host, self.port))
        self.socket.listen(5)
        print(f"Server listening on {self.host}:{self.port}")

    def broadcast(self, message, client_socket):
        for client in self.clients:
            if client != client_socket:
                try:
                    client.send(message)
                except:
                    self.clients.remove(client)

    def handle_client(self, client_socket):
        while True:
            try:
                message = client_socket.recv(1024)
                if not message:
                    break
                self.broadcast(message, client_socket)
            except:
                self.clients.remove(client_socket)
                client_socket.close()
                break

    def start(self):
        while True:
            client_socket, client_address = self.socket.accept()
            print(f"Client {client_address} connected")
            self.clients.append(client_socket)
            threading.Thread(target=self.handle_client, args=(client_socket,)).start()

def main():
    server = Server("localhost", 8050)
    server.start()

if __name__ == "__main__":
    main()


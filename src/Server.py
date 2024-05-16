import socket
import threading
CHUNK_SIZE=2048
class Server:
    def __init__(self, port):
        self.host = self.get_ip_address()
        self.port = port
        self.clients = []
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind((self.host, self.port))
        self.socket.listen(5)
        print(f"Server listening on {self.host}:{self.port}")

    def get_ip_address(self):
        """
        Get the IP address of the server
        """
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip = s.getsockname()[0]
        s.close()
        return ip

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
                message = client_socket.recv(CHUNK_SIZE)
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
    server_port = int(input("Enter the server port: "))
    server = Server(server_port)
    server.start()

if __name__ == "__main__":
    main()
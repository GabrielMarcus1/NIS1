import socket
import os
import tkinter as tk
from tkinter import simpledialog, filedialog, messagebox
import base64
import os
import tkinter as tk
from tkinter import simpledialog, filedialog, messagebox
import base64
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, rsa
from cryptography.hazmat.primitives import serialization, rsa

class Client:
    def __init__(self, master, host, port):
        self.master = master
        self.host = host
        self.port = port
        self.setup_ui()
    def __init__(self, master, host, port):
        self.master = master
        self.host = host
        self.port = port
        self.setup_ui()
        self.client_private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        self.client_public_key = self.client_private_key.public_key()
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.connect()

    def setup_ui(self):
        self.master.title("Client Interface")
        tk.Label(self.master, text="Select Action:").pack()
        tk.Button(self.master, text="Send Text", command=self.send_text).pack()
        tk.Button(self.master, text="Upload Image", command=self.send_image).pack()
        tk.Button(self.master, text="Exit", command=self.close_connection).pack()
        self.connect()

    def setup_ui(self):
        self.master.title("Client Interface")
        tk.Label(self.master, text="Select Action:").pack()
        tk.Button(self.master, text="Send Text", command=self.send_text).pack()
        tk.Button(self.master, text="Upload Image", command=self.send_image).pack()
        tk.Button(self.master, text="Exit", command=self.close_connection).pack()

    def connect(self):
        self.socket.connect((self.host, self.port))
    def connect(self):
        self.socket.connect((self.host, self.port))
        self.socket.send(self.client_public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ))

    def send_text(self):
        text = simpledialog.askstring("Input", "Enter your message:", parent=self.master)
        if text:
            encoded_text = base64.b64encode(text.encode()).decode()
            self.socket.sendall('TEXT'.encode())
            self.socket.sendall(str(len(encoded_text)).encode())
            self.socket.sendall(encoded_text.encode())
    def send_text(self):
        text = simpledialog.askstring("Input", "Enter your message:", parent=self.master)
        if text:
            encoded_text = base64.b64encode(text.encode()).decode()
            self.socket.sendall('TEXT'.encode())
            self.socket.sendall(str(len(encoded_text)).encode())
            self.socket.sendall(encoded_text.encode())

    def send_image(self):
        filepath = filedialog.askopenfilename(title="Select image", filetypes=(("jpeg files", "*.jpg"), ("png files", "*.png"), ("all files", "*.*")))
        if filepath:
            with open(filepath, 'rb') as file:
                image_data = file.read()
            base64_encoded_data = base64.b64encode(image_data).decode()
            self.socket.sendall('IMAGE'.encode())
            self.socket.sendall(str(len(base64_encoded_data)).encode())
            self.socket.sendall(base64_encoded_data.encode())
    def send_image(self):
        filepath = filedialog.askopenfilename(title="Select image", filetypes=(("jpeg files", "*.jpg"), ("png files", "*.png"), ("all files", "*.*")))
        if filepath:
            with open(filepath, 'rb') as file:
                image_data = file.read()
            base64_encoded_data = base64.b64encode(image_data).decode()
            self.socket.sendall('IMAGE'.encode())
            self.socket.sendall(str(len(base64_encoded_data)).encode())
            self.socket.sendall(base64_encoded_data.encode())

    def close_connection(self):
        self.socket.close()
        self.master.quit()
        self.master.quit()

def main():
    root = tk.Tk()
    client = Client(root, "localhost", 12345)
    root.mainloop()
    root = tk.Tk()
    client = Client(root, "localhost", 12345)
    root.mainloop()

if __name__ == "__main__":
    main()

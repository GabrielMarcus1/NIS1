# import socket
# import os
# import tkinter as tk
# from tkinter import simpledialog, filedialog, messagebox
# import base64
# import os
# import tkinter as tk
# from tkinter import simpledialog, filedialog, messagebox
# import base64
# from cryptography.hazmat.backends import default_backend

# from security_utils import gen_private_key
# from cryptography.hazmat.primitives import serialization


# class Client:
#     def __init__(self, master, host, port):
#         self.master = master
#         self.host = host
#         self.port = port
#         self.setup_ui()
#     def __init__(self, master, host, port):
#         self.master = master
#         self.host = host
#         self.port = port
#         self.setup_ui()
#         self.client_private_key = gen_private_key()
        
#         self.client_public_key = self.client_private_key.public_key()
#         self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
#         self.connect()

#     def setup_ui(self):
#         self.master.title("Client Interface")
#         tk.Label(self.master, text="Select Action:").pack()
#         tk.Button(self.master, text="Send Text", command=self.send_text).pack()
#         tk.Button(self.master, text="Upload Image", command=self.send_image).pack()
#         tk.Button(self.master, text="Exit", command=self.close_connection).pack()
#         self.connect()

#     def setup_ui(self):
#         self.master.title("Client Interface")
#         tk.Label(self.master, text="Select Action:").pack()
#         tk.Button(self.master, text="Send Text", command=self.send_text).pack()
#         tk.Button(self.master, text="Upload Image", command=self.send_image).pack()
#         tk.Button(self.master, text="Exit", command=self.close_connection).pack()

#     def connect(self):
#         self.socket.connect((self.host, self.port))
#     def connect(self):
#         self.socket.connect((self.host, self.port))
#         self.socket.send(self.client_public_key.public_bytes(
#             encoding=serialization.Encoding.PEM,
#             format=serialization.PublicFormat.SubjectPublicKeyInfo
#         ))

#     def send_text(self):
#         text = simpledialog.askstring("Input", "Enter your message:", parent=self.master)
#         if text:
#             encoded_text = base64.b64encode(text.encode()).decode()
#             self.socket.sendall('TEXT'.encode())
#             self.socket.sendall(str(len(encoded_text)).encode())
#             self.socket.sendall(encoded_text.encode())
#     def send_text(self):
#         text = simpledialog.askstring("Input", "Enter your message:", parent=self.master)
#         if text:
#             encoded_text = base64.b64encode(text.encode()).decode()
#             self.socket.sendall('TEXT'.encode())
#             self.socket.sendall(str(len(encoded_text)).encode())
#             self.socket.sendall(encoded_text.encode())

#     def send_image(self):
#         filepath = filedialog.askopenfilename(title="Select image", filetypes=(("jpeg files", "*.jpg"), ("png files", "*.png"), ("all files", "*.*")))
#         if filepath:
#             with open(filepath, 'rb') as file:
#                 image_data = file.read()
#             base64_encoded_data = base64.b64encode(image_data).decode()
#             self.socket.sendall('IMAGE'.encode())
#             self.socket.sendall(str(len(base64_encoded_data)).encode())
#             self.socket.sendall(base64_encoded_data.encode())
#     def send_image(self):
#         filepath = filedialog.askopenfilename(title="Select image", filetypes=(("jpeg files", "*.jpg"), ("png files", "*.png"), ("all files", "*.*")))
#         if filepath:
#             with open(filepath, 'rb') as file:
#                 image_data = file.read()
#             base64_encoded_data = base64.b64encode(image_data).decode()
#             self.socket.sendall('IMAGE'.encode())
#             self.socket.sendall(str(len(base64_encoded_data)).encode())
#             self.socket.sendall(base64_encoded_data.encode())

#     def close_connection(self):
#         self.socket.close()
#         self.master.quit()
#         self.master.quit()

# def main():
#     root = tk.Tk()
#     client = Client(root, "localhost", 8000)
#     root.mainloop()

# if __name__ == "__main__":
#     main()
import base64
import json
import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, Button, filedialog
import os
from tkinter import simpledialog
from generate_message import constuct_pgp_message
from message_utils import create_string, decrypt_message_PGP, save_file
from security_utils import gen_private_key, gen_public_key, load_key 

class GUIClient:
    def __init__(self, master, host, port):
        self.master = master
        self.host = host
        self.port = port
        self.client_private_key = load_key("private_key.pem", "private")
        self.client_public_key = load_key("public_key.pem", "public")
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.host, self.port))
        self.setup_ui()
        threading.Thread(target=self.receive_messages).start()

    def setup_ui(self):
       self.master.title("Chat Client")
       self.text_area = scrolledtext.ScrolledText(self.master, wrap=tk.WORD)
       self.text_area.pack(padx=10, pady=10)
       self.text_area.config(state=tk.DISABLED)
       self.entry = tk.Entry(self.master)
       self.entry.pack(padx=10, pady=5, fill=tk.X, side=tk.LEFT)
       self.send_button = Button(self.master, text="Send Text", command=self.send_text_message)
       self.send_button.pack(padx=5, pady=5, side=tk.LEFT)
       self.send_image_button = Button(self.master, text="Send Image", command=self.send_image_message)
       self.send_image_button.pack(padx=5, pady=5, side=tk.LEFT)
    # Bind the save_image_message method to the Send Image button
    #    self.send_image_button.bind("<Button-1>", self.save_image_message)

    def send_text_message(self):
        message = self.entry.get()
        message= constuct_pgp_message(message,self.client_private_key,self.client_public_key)
        self.entry.delete(0, tk.END)
    
        self.socket.send(message)

    def send_image_message(self):
        file_path = filedialog.askopenfilename()
        print(file_path)
        if file_path:
            caption = simpledialog.askstring("Input", "Enter a caption for the image:", parent=self.master)
            with open(file_path, "rb") as file:
                image_data = file.read()
            # image_message = {
            #     "type": "image",
            #     "caption": caption,
            #     "image_data": base64.b64encode(image_data).decode()
            # }
            # message = json.dumps(image_message)
            image_data=base64.b64encode(image_data).decode()
            encrypted_message = constuct_pgp_message(image_data, self.client_private_key,self.client_public_key)
            self.socket.send(encrypted_message)

    

    def receive_messages(self):
        while True:
            try:
                message = self.socket.recv(1024)
                # print(message)
                output= decrypt_message_PGP(message, self.client_private_key)

                # save_file(output)
                print("the output is: "+ output)
                if output!= "Error":
                    self.text_area.config(state=tk.NORMAL)
                    self.text_area.insert(tk.END, output + "\n")
                    self.text_area.config(state=tk.DISABLED)
                else:
                    break
            except Exception as e:
                print(f"Error receiving message: {e}")
                break


    
                  
    def close_connection(self):
        self.socket.close()
        self.master.quit()

    # def save_image_message(self):
    #     file_path = filedialog.asksaveasfilename(defaultextension=".jpg", filetypes=[("JPEG files", "*.jpg"), ("All files", "*.*")])
    #     if file_path:
    #         with open(file_path, "wb") as file:
    #             file.write(self.socket.recv(1024))

def main():
    # Create "photos" folder if it doesn't exist
    os.makedirs("photos", exist_ok=True)
    
    root = tk.Tk()
    client = GUIClient(root, "localhost", 8040)
    root.mainloop()

if __name__ == "__main__":
    main()




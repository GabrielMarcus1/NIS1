import base64
import json
import socket
import threading
import tkinter as tk
from tkinter import scrolledtext, Button, filedialog, simpledialog
from generate_message import constuct_pgp_message
from message_utils import create_string, decrypt_message_PGP
from security_utils import gen_private_key, gen_public_key, load_key, ensure_keys

CHUNK_SIZE = 2048


class GUIClient:
    def __init__(self, master, host, port):
        self.master = master
        self.host = host
        self.port = port
        ensure_keys() # ensure keys are generated before loading 
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
        self.send_button = Button(
            self.master, text="Send Text", command=self.send_text_message
        )
        self.send_button.pack(padx=5, pady=5, side=tk.LEFT)
        self.send_image_button = Button(
            self.master, text="Send Image", command=self.send_image_message
        )
        self.send_image_button.pack(padx=5, pady=5, side=tk.LEFT)

    def send_image_message(self):
        file_path = filedialog.askopenfilename()
        if not file_path:
            print("File not selected")
            return
        with open(file_path, "rb") as file:
            image_data = file.read()

        encoded_data = base64.b64encode(image_data).decode("utf-8")
        encrypted_message = constuct_pgp_message(
            encoded_data, self.client_private_key, self.client_public_key
        )
        header = json.dumps({"type": "image", "length": len(encrypted_message)})
        self.socket.sendall(header.encode("utf-8"))
        self.socket.sendall(encrypted_message)

    def send_text_message(self):

        message = self.entry.get()
        encrypted_message = constuct_pgp_message(
            message, self.client_private_key, self.client_public_key
        )
        self.entry.delete(0, tk.END)
        header = json.dumps({"type": "text", "length": len(encrypted_message)})
        self.socket.sendall(header.encode("utf-8"))
        self.socket.sendall(encrypted_message)

    def receive_messages(self):
        while True:
            try:
                header = self.socket.recv(1024).decode("utf-8")
                if header:
                    data = json.loads(header)
                    message_type = data["type"]
                    message_length = data["length"]
                    if message_type == "text":
                        self.receive_text_message(message_length)
                    elif message_type == "image":
                        self.receive_image_message(message_length)
                else:
                    break
            except Exception as e:
                print(f"Error receiving message: {e}")
                break

    def receive_text_message(self, message_length):
        encrypted_message = self.socket.recv(message_length)
        decrypted_message = decrypt_message_PGP(
            encrypted_message, self.client_private_key
        )
        if decrypted_message:
            decrypted_message_json = json.loads(decrypted_message)
            message = decrypted_message_json["Image"]
            self.text_area.config(state=tk.NORMAL)
            self.text_area.insert(tk.END, message + "\n")
            self.text_area.config(state=tk.DISABLED)

    def receive_image_message(self, image_size):
        received_chunks = b""
        while image_size > 0:

            chunk = self.socket.recv(min(CHUNK_SIZE, image_size))
            if not chunk:
                break
            received_chunks += chunk
            image_size -= len(chunk)
        data_json = decrypt_message_PGP(received_chunks, self.client_private_key)
        data = json.loads(data_json)
        image = data["Image"]
        caption = data["Caption"]
        image_data = base64.b64decode(image)
        self.text_area.insert(tk.END, caption + "\n")
        self.save_image_message(image_data)

        # image_data = base64.b64decode(recievedData)
        # print("Image successfully recieved")
        # self.save_image_message(image_data)

    # def recieve_photo():

    #     while filesize >0
    #        chunk = clientSocket.recv(min(BLOCKSIZE, file_size))
    #        if not chunk:
    #            break
    #        recievedData+= chunk
    #        file_size -= len(chunk)

    def close_connection(self):
        self.socket.close()
        self.master.quit()

    def save_image_message(self, data):
        file_path = filedialog.asksaveasfilename(
            defaultextension=".png",
            filetypes=[("PNG files", "*.png"), ("All files", "*.*")],
        )
        if file_path:
            with open(file_path, "wb") as file:
                file.write(data)


def main():
    # Create "photos" folder if it doesn't exist
    # os.makedirs("photos", exist_ok=True)

    # root = tk.Tk()
    # client = GUIClient(root, "localhost", 8060)
    # root.mainloop()
    root = tk.Tk()
    root.withdraw()  # Hide the root window
    server_ip = simpledialog.askstring("Server IP", "Enter the server IP address:")
    socket = simpledialog.askinteger(
        "Socket", "Enter the socket you wish to connect to:"
    )
    root.deiconify()  # Show the root window
    if server_ip:
        client = GUIClient(root, server_ip, socket)
        root.mainloop()
    else:
        print("No IP address entered, exiting.")
        root.destroy()


if __name__ == "__main__":
    main()

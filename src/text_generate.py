# program creates a text with caption and image.
import os
from datetime import datetime
import tkinter as tk
from tkinter import filedialog
from security import generate_hash_message
import json
import base64

  

def create_text():
    print("Select an image")
    root = tk.Tk()
    root.withdraw()

    image = filedialog.askopenfilename(filetypes=[("Image files", "*.jpg;*.jpeg;*.png")])

    caption = input("Enter a Caption:\n")

    filename = os.path.basename(image)
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    with open(image, "rb") as image:
        data = image.read()

    # Base64 encode the image data
    data_b64 = base64.b64encode(data).decode('utf-8')

    metadata = {
        "Caption": caption,
        "Image": data_b64
    }

    message = {
        "Filename": filename,
        "Timestamp": timestamp,
        "Data": metadata
    }
    return message










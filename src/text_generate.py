# program creates a text with caption and image.
import os
from datetime import datetime
import tkinter as tk
from tkinter import filedialog
from security import generate_hash_message
import json
import base64

# returns image filepath
def select_image():
    root = tk.Tk()
    root.withdraw()

    image_path = filedialog.askopenfilename(filetypes=[("Image files", "*.jpg;*.jpeg;*.png")])

    return image_path


# generate PGP message
def generate_message(image_path, caption):

    filename = os.path.basename(image_path)
    timestamp = datetime.now().strftime('%Y-%m-%d %H:%M:%S')

    with open(image_path, "rb") as image:
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


def create_text():
    print("Select an image")
    image = select_image()

    caption = input("Enter a Caption:\n")

    return generate_message(image, caption)










# program implements PGP message generation
import pgpy
import os
from datetime import datetime

def generate_pgp_message(text, file_path):
    filename = os.path.basename(file_path)
    timestamp = datetime.now()

    # Create PGP message container
    message = pgpy.PGPMessage.new(filename)
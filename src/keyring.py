import os
from Crypto.PublicKey import RSA

# Function to add a public key to the key ring
def add_key(key_ring, identifier, public_key):
    """Add a public key to the key ring."""
    key_ring[identifier] = public_key

# Function to retrieve a public key from the key ring
def get_key(key_ring, identifier):
    """Retrieve a public key from the key ring."""
    return key_ring.get(identifier)

# Function to remove a public key from the key ring
def remove_key(key_ring, identifier):
    """Remove a public key from the key ring."""
    key_ring.pop(identifier, None)

# Function to list all identifiers in the key ring
def list_keys(key_ring):
    """List all identifiers in the key ring."""
    return list(key_ring.keys())

# Example key ring dictionary to store public keys
key_ring = {}


def load_key(key_path, key_type):
    full_path = os.path.join("keys", key_path)
    if not os.path.exists(full_path):
        raise FileNotFoundError(f"{key_type.capitalize()} key not found at {full_path}.")
    
    with open(full_path, "rb") as key_file:
        key = RSA.import_key(key_file.read())

    return key

if __name__ == "__main__":
    # dummy data 
    public_key1 = "public_key_data_1"
    public_key2 = "public_key_data_2"

    # Adding keys to the key ring
    add_key(key_ring, 'user1', public_key1)
    add_key(key_ring, 'user2', public_key2)

    # Retrieving a key from the key ring
    print("Retrieved Key for user1:", get_key(key_ring, 'user1'))

    # Listing all keys in the key ring
    print("All keys in the key ring:", list_keys(key_ring))

    # Removing a key from the key ring
    remove_key(key_ring, 'user1')
    print("Key ring after removing user1:", list_keys(key_ring))
    
    

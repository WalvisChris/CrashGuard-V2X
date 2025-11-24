from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import serialization
import os

GROUP_KEY_PATH = "keys/group_key.bin"               # has to be .bin
PRIVATE_KEY_PATH = "keys/sender_private_key.pem"    # has to be .pem
PUBLIC_KEY_PATH = "keys/sender_public_key.pem"      # has to be .pem

def create_keys() -> None:
    
    # --- Create group key ---
    group_key = os.urandom(16)

    # --- Save group key ---
    with open(GROUP_KEY_PATH, "wb") as f:
        f.write(group_key)
    print("GROUP_KEY aangemaakt.")

    # --- Sender Key Pair Generation and Saving ---
    private_key = ec.generate_private_key(ec.SECP256R1())

    # Save Sender Private Key
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    with open(PRIVATE_KEY_PATH, "wb") as f:
        f.write(private_pem)

    # Save Sender Public Key (The part that needed fixing!)
    public_key = private_key.public_key()
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open(PUBLIC_KEY_PATH, "wb") as f:
        f.write(public_pem)
    
    print("SENDER_KEYS aangemaakt.")

if __name__ == "__main__":
    os.system('cls')
    create_keys()
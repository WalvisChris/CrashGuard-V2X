# This file is necessary to make this directory a package.
import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (
    Encoding, PrivateFormat, PublicFormat, NoEncryption,
    load_pem_private_key, load_pem_public_key
)
from .terminal.TerminalInterface import TerminalInterface

# Key file paths
DATA_DIR = "data/"
PRIVATE_KEY_FILE = os.path.join(DATA_DIR, "private_key.pem")
PUBLIC_KEY_FILE = os.path.join(DATA_DIR, "public_key.pem")
PSK_KEY_FILE = os.path.join(DATA_DIR, "psk.txt")
MESSAGE_FILE = os.path.join(DATA_DIR, "msg.txt")

# Ensure key directory exists
os.makedirs(DATA_DIR, exist_ok=True)

# Package-level variables
PRIVATE_KEY = None
PUBLIC_KEY = None
PSK = None
MESSAGE = None
terminal = TerminalInterface()  # terminal instance

def createKeys():
    global PRIVATE_KEY, PUBLIC_KEY, PSK

    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    # Save private key
    private_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption()
    )
    with open(PRIVATE_KEY_FILE, "wb") as f:
        f.write(private_pem)
    print("[CrashGuardIEEE]: private key aangemaakt")

    # Save public key
    public_pem = public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo
    )
    with open(PUBLIC_KEY_FILE, "wb") as f:
        f.write(public_pem)
    print("[CrashGuardIEEE]: public key aangemaakt")

    # Save PSK
    psk = os.urandom(16)
    with open(PSK_KEY_FILE, "wb") as f:
        f.write(psk)
    print("[CrashGuardIEEE]: psk aangemaakt")

    # Set package-level variables
    PRIVATE_KEY = private_key
    PUBLIC_KEY = public_key
    PSK = psk

def loadKeys():
    global PRIVATE_KEY, PUBLIC_KEY, PSK

    # If any key missing, create all keys
    if not (os.path.exists(PRIVATE_KEY_FILE) and os.path.exists(PUBLIC_KEY_FILE) and os.path.exists(PSK_KEY_FILE)):
        createKeys()

    # Load private key
    with open(PRIVATE_KEY_FILE, "rb") as f:
        PRIVATE_KEY = load_pem_private_key(f.read(), password=None)

    # Load public key
    with open(PUBLIC_KEY_FILE, "rb") as f:
        PUBLIC_KEY = load_pem_public_key(f.read())

    # Load PSK
    with open(PSK_KEY_FILE, "rb") as f:
        PSK = f.read()

    print("[CrashGuardIEEE]: keys and PSK loaded successfully")

def saveMessage(message: bytes):
    global MESSAGE
    
    MESSAGE = message
    with open(MESSAGE_FILE, "wb") as f:
        f.write(message)

def loadMessage():
    global MESSAGE
    with open(MESSAGE_FILE, "rb") as f:
        MESSAGE = f.read()

# Automatically load keys when package is imported
loadKeys()
loadMessage()

# Import submodules
from . import encoder
from . import decoder
from . import asn1
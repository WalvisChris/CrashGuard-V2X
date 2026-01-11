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
ROOT_CA_PRIVATE_KEY_FILE = os.path.join(DATA_DIR, "root_ca_private_key.pem")
ROOT_CA_PUBLIC_KEY_FILE = os.path.join(DATA_DIR, "root_ca_public_key.pem")
SENDER_PRIVATE_KEY_FILE = os.path.join(DATA_DIR, "sender_private_key.pem")
SENDER_PUBLIC_KEY_FILE = os.path.join(DATA_DIR, "sender_public_key.pem")
PSK_KEY_FILE = os.path.join(DATA_DIR, "psk.txt")
MESSAGE_FILE = os.path.join(DATA_DIR, "msg.txt")

# Ensure key directory exists
os.makedirs(DATA_DIR, exist_ok=True)

# Package-level variables
ROOT_CA_PRIVATE_KEY = None
ROOT_CA_PUBLIC_KEY = None
SENDER_PRIVATE_KEY = None
SENDER_PUBLIC_KEY = None
PSK = None
MESSAGE = None
terminal = TerminalInterface()  # terminal instance

def createSenderKeys():
    global SENDER_PRIVATE_KEY, SENDER_PUBLIC_KEY

    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    # Save private key
    private_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption()
    )
    with open(SENDER_PRIVATE_KEY_FILE, "wb") as f:
        f.write(private_pem)
    print("[CrashGuardIEEE]: Sender private key aangemaakt")

    # Save public key
    public_pem = public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo
    )
    with open(SENDER_PUBLIC_KEY_FILE, "wb") as f:
        f.write(public_pem)
    print("[CrashGuardIEEE]: Sender public key aangemaakt")

    # Set package-level variables
    SENDER_PRIVATE_KEY = private_key
    SENDER_PUBLIC_KEY = public_key

def createRootCAKeys():
    global ROOT_CA_PRIVATE_KEY, ROOT_CA_PUBLIC_KEY

    private_key = ec.generate_private_key(ec.SECP256R1())
    public_key = private_key.public_key()

    # Save private key
    private_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption()
    )
    with open(ROOT_CA_PRIVATE_KEY_FILE, "wb") as f:
        f.write(private_pem)
    print("[CrashGuardIEEE]: Root CA private key aangemaakt")

    # Save public key
    public_pem = public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo
    )
    with open(ROOT_CA_PUBLIC_KEY_FILE, "wb") as f:
        f.write(public_pem)
    print("[CrashGuardIEEE]: Root CA public key aangemaakt")

    # Set package-level variables
    ROOT_CA_PRIVATE_KEY = private_key
    ROOT_CA_PUBLIC_KEY = public_key

def createPSK():
    global PSK

    psk = os.urandom(16)
    with open(PSK_KEY_FILE, "wb") as f:
        f.write(psk)
    print("[CrashGuardIEEE]: psk aangemaakt")

    PSK = psk

def loadKeys():
    global ROOT_CA_PRIVATE_KEY, ROOT_CA_PUBLIC_KEY, SENDER_PRIVATE_KEY, SENDER_PUBLIC_KEY, PSK

    # If any key missing, create all keys
    if not (os.path.exists(SENDER_PRIVATE_KEY_FILE) and os.path.exists(SENDER_PUBLIC_KEY_FILE)):
        createSenderKeys()

    if not (os.path.exists(ROOT_CA_PRIVATE_KEY_FILE) and os.path.exists(ROOT_CA_PUBLIC_KEY_FILE)):
        createRootCAKeys()
    
    if not (os.path.exists(PSK_KEY_FILE)):
        createPSK()

    # Load root ca keys
    with open(ROOT_CA_PRIVATE_KEY_FILE, "rb") as f:
        ROOT_CA_PRIVATE_KEY = load_pem_private_key(f.read(), password=None)

    with open(ROOT_CA_PUBLIC_KEY_FILE, "rb") as f:
        ROOT_CA_PUBLIC_KEY = load_pem_public_key(f.read())

    # Load sender keys
    with open(SENDER_PRIVATE_KEY_FILE, "rb") as f:
        SENDER_PRIVATE_KEY = load_pem_private_key(f.read(), password=None)

    with open(SENDER_PUBLIC_KEY_FILE, "rb") as f:
        SENDER_PUBLIC_KEY = load_pem_public_key(f.read())

    # Load PSK
    with open(PSK_KEY_FILE, "rb") as f:
        PSK = f.read()

    print("[CrashGuardIEEE]: root ca & sender keys and PSK loaded successfully")

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
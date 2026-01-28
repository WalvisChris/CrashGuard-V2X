"""
Dit script definieert en bevat alle code van CrashGuardIEEE
het is de hoofd-library die verschillende waardes en functies bevat die allemaal aan te roepen zijn vanuit dit script. 
"""

# Als eerst importeren we open source libraries. Deze zijn verantwoordenlijk voor o.a. de cryptografische functies
import os
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.serialization import (Encoding, PrivateFormat, PublicFormat, NoEncryption, load_pem_private_key, load_pem_public_key)
from .terminal.TerminalInterface import TerminalInterface

# Daarna geven we aan in welke bestanden de sleutels en berichten te vinden zijn.
DATA_DIR = "data/"
ROOT_CA_PRIVATE_KEY_FILE = os.path.join(DATA_DIR, "root_ca_private_key.pem")
ROOT_CA_PUBLIC_KEY_FILE = os.path.join(DATA_DIR, "root_ca_public_key.pem")
SENDER_PRIVATE_KEY_FILE = os.path.join(DATA_DIR, "sender_private_key.pem")
SENDER_PUBLIC_KEY_FILE = os.path.join(DATA_DIR, "sender_public_key.pem")
PSK_KEY_FILE = os.path.join(DATA_DIR, "psk.txt")
MESSAGE_FILE = os.path.join(DATA_DIR, "msg.txt")
REPLAY_FILE = os.path.join(DATA_DIR, "replay.txt")
os.makedirs(DATA_DIR, exist_ok=True)

# We maken de sleutels hier aan zodat deze aangeroepen kunnen worden als CrashGuardIEEE
ROOT_CA_PRIVATE_KEY = None
ROOT_CA_PUBLIC_KEY = None
SENDER_PRIVATE_KEY = None
SENDER_PUBLIC_KEY = None
PSK = None
MESSAGE = None
terminal = TerminalInterface()
latest_protocol_version = 3

"""
De functie 'createSenderKeys' genereert willekeurige sleutels zodat wij deze kunnen gebruiken voor het ondertekenen van de certificaten.
We genereren een private en public key voor de Pijlwagen.
"""
def createSenderKeys():
    global SENDER_PRIVATE_KEY, SENDER_PUBLIC_KEY # verwijzigen naar de eerder gedefinieerde sleutels van de Pijlwagen

    private_key = ec.generate_private_key(ec.SECP256R1()) # aanmaken van een private key
    public_key = private_key.public_key() # berekenen van de public key op basis van de private key

    # nu wordt de private key omgezet zodat deze in een bestand in de data folder opgeslagen kan worden
    private_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption()
    )

    # nu wordt de sleutel in het bestand gezet
    with open(SENDER_PRIVATE_KEY_FILE, "wb") as f:
        f.write(private_pem)

    # in de terminal is te zien dat de sleutel is aangemaakt
    print("[CrashGuardIEEE]: Sender private key aangemaakt")

    # ook zetten we de public key om zodat deze in een bestand in de data folder opgeslagen kan worden
    public_pem = public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo
    )
    
    # ook deze slaan we op in het bestand
    with open(SENDER_PUBLIC_KEY_FILE, "wb") as f:
        f.write(public_pem)

    # en we krijgen hier ook een bericht van dat het is gelukt
    print("[CrashGuardIEEE]: Sender public key aangemaakt")

    # we slaan de sleutels op in dit script zodat ze aan te roepen zijn vanuit andere bestanden als CrashGuardIEEE.SENDER_PRIVATE_KEY en CrashGuardIEEE.SENDER_PUBLIC_KEY
    SENDER_PRIVATE_KEY = private_key
    SENDER_PUBLIC_KEY = public_key

"""
De functie 'createRootCAKeys' genereert willekeurige sleutels zodat wij deze kunnen gebruiken voor het ondertekenen van de certificaten.
We genereren een private en public key voor de root CA.
"""
def createRootCAKeys():
    global ROOT_CA_PRIVATE_KEY, ROOT_CA_PUBLIC_KEY # verwijzigen naar de eerder gedefinieerde sleutels van de root CA

    private_key = ec.generate_private_key(ec.SECP256R1()) # aanmaken van een private key
    public_key = private_key.public_key() # berekenen van de public key op basis van de private key

    # nu wordt de private key omgezet zodat deze in een bestand in de data folder opgeslagen kan worden
    private_pem = private_key.private_bytes(
        encoding=Encoding.PEM,
        format=PrivateFormat.PKCS8,
        encryption_algorithm=NoEncryption()
    )

    # nu wordt de sleutel in het bestand gezet
    with open(ROOT_CA_PRIVATE_KEY_FILE, "wb") as f:
        f.write(private_pem)

    # in de terminal is te zien dat de sleutel is aangemaakt
    print("[CrashGuardIEEE]: Root CA private key aangemaakt")

    # ook zetten we de public key om zodat deze in een bestand in de data folder opgeslagen kan worden
    public_pem = public_key.public_bytes(
        encoding=Encoding.PEM,
        format=PublicFormat.SubjectPublicKeyInfo
    )

    # ook deze slaan we op in het bestand
    with open(ROOT_CA_PUBLIC_KEY_FILE, "wb") as f:
        f.write(public_pem)
    
    # en we krijgen hier ook een bericht van dat het is gelukt
    print("[CrashGuardIEEE]: Root CA public key aangemaakt")

    # we slaan de sleutels op in dit script zodat ze aan te roepen zijn vanuit andere bestanden als CrashGuardIEEE.ROOT_CA_PRIVATE_KEY en CrashGuardIEEE.ROOT_CA_PUBLIC_KEY
    ROOT_CA_PRIVATE_KEY = private_key
    ROOT_CA_PUBLIC_KEY = public_key


"""
De functie 'createPSK' genereert een willekeurige pre-shared key zodat wij deze kunnen gebruiken voor het encrypten van het bericht.
"""
def createPSK():
    global PSK # verwijzigen naar de eerder gedefinieerde PSK (pre-shared key)

    psk = os.urandom(16) # pre-shared key wordt aangemaakt als willekeurige getal met een size van 16 bytes
    
    # de pre-shared key wordt opgeslagen in een bestand
    with open(PSK_KEY_FILE, "wb") as f:
        f.write(psk)

    # in de terminal krijgen we een melding dat de pre-shared key is aangemaakt
    print("[CrashGuardIEEE]: psk aangemaakt")

    # we slaan de pre-shared key op in dit script zodat hij vanuit andere scripts is aan te roepen als CrashGuardIEEE.PSK
    PSK = psk

"""
De functie 'loadKeys' laat de sleutels vanuit de bestanden. Dit gebeurt 1x aan het begin van het programma zodat dit later geen tijd kost.
"""
def loadKeys():
    # Verwijzingen naar de eerder gedefinieerde sleutels
    global ROOT_CA_PRIVATE_KEY, ROOT_CA_PUBLIC_KEY, SENDER_PRIVATE_KEY, SENDER_PUBLIC_KEY, PSK

    # als het bestand met de SENDER keys niet bestaat, voer dan de functie 'createSenderKeys' uit
    if not (os.path.exists(SENDER_PRIVATE_KEY_FILE) and os.path.exists(SENDER_PUBLIC_KEY_FILE)):
        createSenderKeys()

    # als het bestand met de ROOT CA keys niet bestaat, voer dan de functie 'createRootCAKeys' uit
    if not (os.path.exists(ROOT_CA_PRIVATE_KEY_FILE) and os.path.exists(ROOT_CA_PUBLIC_KEY_FILE)):
        createRootCAKeys()
    
    # als het bestand met de pre-shared key niet bestaat, voer dan de functie 'createPSK' uit
    if not (os.path.exists(PSK_KEY_FILE)):
        createPSK()

    # Anders, als de bestanden wel bestaan...
    # lees het bestand met de ROOT CA private key uit en sla deze in dit script op
    with open(ROOT_CA_PRIVATE_KEY_FILE, "rb") as f:
        ROOT_CA_PRIVATE_KEY = load_pem_private_key(f.read(), password=None)

    # lees het bestand met de ROOT CA public key uit en sla deze in dit script op
    with open(ROOT_CA_PUBLIC_KEY_FILE, "rb") as f:
        ROOT_CA_PUBLIC_KEY = load_pem_public_key(f.read())

    # lees het bestand met de SENDER private key uit en sla deze in dit script op
    with open(SENDER_PRIVATE_KEY_FILE, "rb") as f:
        SENDER_PRIVATE_KEY = load_pem_private_key(f.read(), password=None)

    # lees het bestand met de SENDER public key uit en sla deze in dit script op
    with open(SENDER_PUBLIC_KEY_FILE, "rb") as f:
        SENDER_PUBLIC_KEY = load_pem_public_key(f.read())

    # lees het bestand met de pre-shared key uit en sla deze in dit script op
    with open(PSK_KEY_FILE, "rb") as f:
        PSK = f.read()

    # laat in de terminal zien dat de keys succesvol zijn uitgelezen en opgeslagen.
    print("[CrashGuardIEEE]: root ca & sender keys and PSK loaded successfully")

"""
De functie 'saveMessage' slaat een bericht op in het bestand, zodat deze de volgende keer weer kan worden uitgelezen.
Om de functie aan te roepen moet je een bericht als parameter meegeven.
"""
def saveMessage(message: bytes):
    global MESSAGE # verwijzing naar het eerder gedefinieerde bericht
    
    MESSAGE = message # het bericht dat aan deze functie is meegegeven wordt opgeslagen als nieuw bericht

    # het nieuwe bericht wordt ook opgeslagen in het bestand, zodat hij later uitgelezen kan worden
    with open(MESSAGE_FILE, "wb") as f:
        f.write(message)

"""
De functie 'loadMessage' haalt het bericht op vanuit het tekst bestand.
Dit gebeurt 1x aan het begin zodat het later geen tijd kost.
"""
def loadMessage():
    global MESSAGE # verwijzing naar het eerder gedefinieerde bericht

    # bericht wordt uitgelezen uit het bestand
    with open(MESSAGE_FILE, "rb") as f:
        MESSAGE = f.read()

"""
De functie 'saveReplay' zorgt dat we een bericht kunnen opslaan zodat we deze later voor de replay attack kunnen gebruiken.
"""
def saveReplay():
    global MESSAGE # verwijzing naar het eerder gedefinieerde bericht

    # huidige bericht wordt in het bestand opgeslagen
    with open(REPLAY_FILE, "wb") as f:
        f.write(MESSAGE)

"""
De functie 'getReplay' leest de het replay bericht uit voor de replay attack.
"""
def getReplay():
    # replay attack uit het bestand uitlezen
    with open(REPLAY_FILE, "rb") as f:
        replay = f.read()
    
    # replay als waarde teruggeven
    return replay

# De keys en het bericht worden automatisch uitgelezen als dit programma start
loadKeys()
loadMessage()

# verwijzingen naar de tools zodat deze door middel van dit script gebruikt kunnen worden
from . import encoder
from . import decoder
from . import asn1
from .visualizer.visuals import Visualizer
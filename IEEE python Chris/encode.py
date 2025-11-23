from cryptography.hazmat.primitives.asymmetric.utils import decode_dss_signature
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives import hashes, serialization
from pyasn1.codec.der import encoder
from pyasn1.type import univ
from asn1 import *
import time
import os

"""
TODO:
- encode checken
- decode updaten met nieuwe ASN.1
- todo fixes
"""

def demoLog(step:str, output:str) -> None:
    print(f"\n[\033[36m{step}\033[0m]:\n{output}")

def encode_unsecure_message() -> None:
    
    # --- Payload ---
    payload = b"ik ben een pijlwagen"
    demoLog("Payload", payload)

    # --- header ---
    GENERATION_TIME = int(time.time() * 1_000_000)

    header = HeaderInfo()
    header.setComponentByName('psid', 0x20) # TODO fix
    header.setComponentByName('generationTime', GENERATION_TIME)
    header.setComponentByName('expiryTime', GENERATION_TIME + 10_000_000)

    demoLog("HeaderInfo", header)

    # --- ToBeSignedData ---
    tbs = ToBeSignedData()
    tbs.setComponentByName('payload', payload)
    tbs.setComponentByName('headerInfo', header)

    demoLog("ToBeSignedData", tbs)

    # --- Ieee1609Dot2Data ---
    content_choice = Ieee1609Dot2Content()
    content_choice.setComponentByName('unsecuredData', payload)

    demoLog("Ieee1609Dot2Content", content_choice)

    # --- Ieee1609Dot2Data ---
    ieee_msg = Ieee1609Dot2Data()
    ieee_msg.setComponentByName('protocolVersion', 3)
    ieee_msg.setComponentByName('contentType', 0)
    ieee_msg.setComponentByName('content', content_choice)

    final_bytes = encoder.encode(ieee_msg)
    demoLog("Final", final_bytes)

    # --- Send message ---
    with open("IEEE python Chris/msg.txt", "wb") as f:
        f.write(final_bytes)

def encode_signed_message() -> None:
    
    # --- Payload ---
    payload = b"ik ben een pijlwagen"
    demoLog("Payload", payload)

    # --- HeaderInfo ---
    GENERATION_TIME = int(time.time() * 1_000_000)

    header = HeaderInfo()
    header.setComponentByName('psid', 0x20) # TODO fix
    header.setComponentByName('generationTime', GENERATION_TIME)
    header.setComponentByName('expiryTime', GENERATION_TIME + 10_000_000)

    demoLog("HeaderInfo", header)

    # --- ToBeSignedData ---
    tbs = ToBeSignedData()
    tbs.setComponentByName('payload', payload)
    tbs.setComponentByName('headerInfo', header)

    demoLog("TBS Data", tbs)

    tbs_bytes = encoder.encode(tbs)

    with open("keys/sender_private_key.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)
    
    # --- ECDSA sign ---
    signature_der = private_key.sign(tbs_bytes, ec.ECDSA(hashes.SHA256()))
    # DER → raw r||s
    r, s = decode_dss_signature(signature_der)

    # --- Signature ---
    sig = EcdsaP256Signature()
    sig.setComponentByName("r", r)
    sig.setComponentByName("s", s)

    sig_choice = Signature()
    sig_choice.setComponentByName("ecdsaNistP256Signature", sig)

    # --- SignerIdentifier ---
    signer_id = SignerIdentifier()
    signer_id.setComponentByName('certificate', b'pijlwagenCert01')

    # --- SignerInfo ---
    signer = SignerInfo()
    signer.setComponentByName('signer', signer_id)
    signer.setComponentByName('signature', sig_choice)

    demoLog("SignerInfo", signer)

    demoLog("Signature structure", sig_choice)

    # --- SignedData ---
    signed = SignedData()
    signed.setComponentByName("hashId", 0)
    signed.setComponentByName("tbsData", tbs)
    signed.setComponentByName("signerInfo", signer)

    demoLog("SignedData", signed)

    # --- Ieee1609Dot2Content ---
    content = Ieee1609Dot2Content()
    content.setComponentByName("signedData", signed)

    # --- Ieee1609Dot2Data ---
    msg = Ieee1609Dot2Data()
    msg.setComponentByName("protocolVersion", 3)
    msg.setComponentByName("contentType", 1)
    msg.setComponentByName("content", content)

    final_bytes = encoder.encode(msg)
    demoLog("Final Ieee1609Dot2Data", msg)

    # --- Send message ---
    with open("IEEE python Chris/msg.txt", "wb") as f:
        f.write(final_bytes)

def encode_encrypted_message() -> None:
    
    # --- Payload ---
    payload = b"ik ben een pijlwagen"
    demoLog("Payload", payload)

    # --- Header ---
    GENERATION_TIME = int(time.time() * 1_000_000)

    header = HeaderInfo()
    header.setComponentByName('psid', 0x20) # TODO fix
    header.setComponentByName('generationTime', GENERATION_TIME)
    header.setComponentByName('expiryTime', GENERATION_TIME + 10_000_000)   # optioneel
    demoLog("HeaderInfo", header)

    # --- ToBeSignedData ---
    tbs = ToBeSignedData()
    tbs.setComponentByName('payload', payload)
    tbs.setComponentByName('headerInfo', header)
    demoLog("ToBeSignedData", tbs)

    # --- Encryption ---
    with open("keys/group_key.bin", "rb") as f:
        GROUP_KEY = f.read()

    NONCE = os.urandom(13)
    aesccm = AESCCM(GROUP_KEY, tag_length=16)
    ciphertext_and_tag = aesccm.encrypt(NONCE, payload, associated_data=None)
    ciphertext = ciphertext_and_tag[:-16]
    icv = ciphertext_and_tag[-16:]  # icv = ccm tag

    # --- RecipientInfo ---
    recipient = RecipientInfo()
    recipient.setComponentByName('recipientID', 'group_01')

    recipients_seq = univ.SequenceOf(componentType=RecipientInfo())
    recipients_seq.append(recipient)

    # --- EncryptedData ---
    enc = EncryptedData()
    enc.setComponentByName('recipients', recipients_seq)
    enc.setComponentByName('ciphertext', ciphertext)
    enc.setComponentByName('icv', icv)
    enc.setComponentByName('symmAlgorithm', univ.ObjectIdentifier('1.2.840.113549.1.9.16.3.12'))    # TODO fix

    demoLog("EncryptedData", enc)

    # --- Ieee1609Dot2Content ---
    content_choice = Ieee1609Dot2Content()
    content_choice.setComponentByName('encryptedData', enc)

    # --- Ieee1609Dot2Data ---
    ieee_msg = Ieee1609Dot2Data()
    ieee_msg.setComponentByName('protocolVersion', 3)
    ieee_msg.setComponentByName('contentType', 2)
    ieee_msg.setComponentByName('content', content_choice)

    final_bytes = encoder.encode(ieee_msg)
    demoLog("Final", final_bytes)

    # --- Send message ---
    with open("IEEE python Chris/msg.txt", "wb") as f:
        f.write(final_bytes)

def encode_enveloped_message() -> None:
    
    # --- Payload ---
    payload = b"ik ben een pijlwagen"
    demoLog("Payload", payload)

    # --- Header ---
    GENERATION_TIME = int(time.time() * 1_000_000)

    header = HeaderInfo()
    header.setComponentByName('psid', 0x20) #TODO fix
    header.setComponentByName('generationTime', GENERATION_TIME)
    header.setComponentByName('expiryTime', GENERATION_TIME + 10_000_000)
    demoLog("HeaderInfo", header)

    # --- ToBeSignedData ---
    tbs = ToBeSignedData()
    tbs.setComponentByName('payload', payload)
    tbs.setComponentByName('headerInfo', header)
    demoLog("ToBeSignedData", tbs)

    tbs_bytes = encoder.encode(tbs)

    with open("keys/sender_private_key.pem", "rb") as f:
        private_key = serialization.load_pem_private_key(f.read(), password=None)

    # --- ECDSA sign ---
    signature_der = private_key.sign(tbs_bytes, ec.ECDSA(hashes.SHA256()))
    # DER → raw r||s
    r, s = decode_dss_signature(signature_der)

    # --- Signature ---
    sig_seq = EcdsaP256Signature()
    sig_seq.setComponentByName('r', r)
    sig_seq.setComponentByName('s', s)

    sig_choice = Signature()
    sig_choice.setComponentByName('ecdsaNistP256Signature', sig_seq)
    demoLog("Signature", sig_choice)

    # --- SignerIdentifier ---
    signer_id = SignerIdentifier()
    signer_id.setComponentByName('certificate', univ.OctetString(b'pijlwagenCert01'))  # TODO fix

    # --- SignerInfo ---
    signer = SignerInfo()
    signer.setComponentByName('signer', signer_id)
    signer.setComponentByName('signature', sig_choice)
    
    # --- SignedData ---
    signed = SignedData()
    signed.setComponentByName('tbsData', tbs)
    signed.setComponentByName('signerInfo', signer)
    
    demoLog("SignedData", signed)

    # --- Encryption ---
    signed_bytes = encoder.encode(signed)

    with open("keys/group_key.bin", "rb") as f:
        GROUP_KEY = f.read()

    NONCE = os.urandom(13)
    aesccm = AESCCM(GROUP_KEY, tag_length=16)
    ciphertext_and_tag = aesccm.encrypt(NONCE, signed_bytes, associated_data=NONCE)
    ciphertext = ciphertext_and_tag[:-16]
    icv = ciphertext_and_tag[-16:]  # icv = ccm tag
    
    # --- Recipient ---
    recipient = RecipientInfo()
    recipient.setComponentByName('recipientID', 'group_01') # TODO fix

    recipients_seq = univ.SequenceOf(componentType=RecipientInfo())
    recipients_seq.append(recipient)

    # --- EnvelopedData ---
    env = EnvelopedData()
    env.setComponentByName('recipients', recipients_seq)
    env.setComponentByName('encryptedContent', ciphertext)
    env.setComponentByName('icv', icv)
    env.setComponentByName('symmAlgorithm', univ.ObjectIdentifier('1.2.840.113549.1.9.16.3.12'))    # TODO fix
    demoLog("EnvelopedData", env)

    # --- Ieee1609Dot2Content ---
    content_choice = Ieee1609Dot2Content()
    content_choice.setComponentByName('envelopedData', env)

    # --- Ieee1609Dot2Data ---
    ieee_msg = Ieee1609Dot2Data()
    ieee_msg.setComponentByName('protocolVersion', 3)
    ieee_msg.setComponentByName('contentType', 3)
    ieee_msg.setComponentByName('content', content_choice)

    final_bytes = encoder.encode(ieee_msg)
    demoLog("Ieee1609Dot2Data (final)", ieee_msg)

    # --- Send message ---
    with open("IEEE python Chris/msg.txt", "wb") as f:
        f.write(final_bytes)

if __name__ == "__main__":
    os.system('cls')
    encode_unsecure_message()
    #encode_signed_message()
    #encode_encrypted_message()
    #encode_enveloped_message()
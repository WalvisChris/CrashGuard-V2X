from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from pyasn1.codec.der import decoder
from asn1 import RecipientInfo, EnvelopedData, Ieee1609Dot2Data, SignedData
import os

def demoLog(step:str, output:str) -> None:
    print(f"\n[\033[36m{step}\033[0m]:\n{output}")

def decode_message() -> None:
    
    # --- 1. Read message ---
    with open("IEEE python Chris/signed_msg.txt", "rb") as f:
        encoded_msg = f.read()

    # --- 2. Decode top-level structure ---
    ieee_msg, _ = decoder.decode(encoded_msg, asn1Spec=Ieee1609Dot2Data())  # ASN.1 decoding

    if int(ieee_msg['contentType']) != 3:
        raise ValueError("Message is not EnvelopedData")

    demoLog("Ieee1609Dot2Data", ieee_msg)

    # --- 3. Decode EncryptedData section ---
    enveloped_bytes = bytes(ieee_msg['content'])
    enveloped, _ = decoder.decode(enveloped_bytes, asn1Spec=EnvelopedData())
    demoLog("EnvelopedData", enveloped)

    ciphertext = bytes(enveloped['encryptedContent'])
    nonce = bytes(enveloped['nonce'])
    ccm_tag = bytes(enveloped['ccmTag'])
    ciphertext_and_tag = ciphertext + ccm_tag

    demoLog("EnvelopedData", enveloped)

    # --- 4. Read group key ---    
    with open("keys/group_key.bin", "rb") as f:
        GROUP_KEY = f.read()
    aesccm = AESCCM(GROUP_KEY, tag_length=16)

    # --- 5. Decrypt AES-CCM ---
    try:
        signed_bytes = aesccm.decrypt(nonce, ciphertext_and_tag, associated_data=None)
        demoLog("Decrypted SignedData", signed_bytes)
    except Exception as e:
        demoLog("AES-CCM decryption failed", e)
        return
    
    # --- 6. Decode SignedData ---
    signed_data, _ = decoder.decode(signed_bytes, asn1Spec=SignedData())
    demoLog("SignedData", signed_data)

    # --- 7. (Optioneel) signature verification ---

    # --- 8. (Optioneel) generation time verification ---

if __name__ == "__main__":
    os.system('cls')
    decode_message()
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from pyasn1.codec.der import decoder
from asn1 import RecipientInfo, EnvelopedData, Ieee1609Dot2Data, SignedData
import os

def demoLog(step:str, output:str) -> None:
    print(f"\n[\033[36m{step}\033[0m]:\n{output}")

def decode_message() -> None:
    
    # --- Read message ---
    with open("IEEE python Chris/signed_msg.txt", "rb") as f:
        encoded_msg = f.read()

    # --- Decode top-level structure ---
    ieee_msg, _ = decoder.decode(encoded_msg, asn1Spec=Ieee1609Dot2Data())  # ASN.1 decoding

    demoLog("Ieee1609Dot2Data", ieee_msg)

    content_type = int(ieee_msg['contentType'])
    content_bytes = bytes(ieee_msg['content'])

    # --- Verwerk contentType ---
    if content_type == 0:   # unsecureData
        payload = content_bytes
        demoLog("Unsecure payload", payload)

    elif content_type == 1: # signedData
        signed_data, _ = decoder.decode(content_bytes, asn1Spec=SignedData())
        demoLog("SignedData", signed_data)
        # TODO: signature verification

    elif content_type == 2: # encryptedData
        enc_data, _ = decoder.decode(content_bytes)
        ciphertext = bytes(enc_data['ciphertext'])
        nonce = bytes(enc_data['nonce'])
        ccm_tag = bytes(enc_data['ccmTag'])
        ciphertext_and_tag = ciphertext + ccm_tag

        with open("keys/group_key.bin", "rb") as f:
            GROUP_KEY = f.read()
        aesccm = AESCCM(GROUP_KEY, tag_length=16)

        try:
            payload = aesccm.decrypt(nonce, ciphertext_and_tag, associated_data=None)
            demoLog("Decrypted payload", payload)
        except Exception as e:
            demoLog("Decryption failed", e)
    
    elif content_type == 3: # envelopedData
        enveloped, _ = decoder.decode(content_bytes, asn1Spec=EnvelopedData())
        ciphertext = bytes(enveloped['encryptedContent'])
        nonce = bytes(enveloped['nonce'])
        ccm_tag = bytes(enveloped['ccmTag'])
        ciphertext_and_tag = ciphertext + ccm_tag

        with open("keys/group_key.bin", "rb") as f:
            GROUP_KEY = f.read()
        aesccm = AESCCM(GROUP_KEY, tag_length=16)

        try:
            signed_bytes = aesccm.decrypt(nonce, ciphertext_and_tag, associated_data=None)
            demoLog("Decrypted SignedData bytes", signed_bytes)
        except Exception as e:
            demoLog("AES-CCM decryption failed", e)
            return
        
        signed_data, _ = decoder.decode(signed_bytes, asn1Spec=SignedData())
        demoLog("SignedData", signed_data)
        # TODO: signature verification

    else:
        raise ValueError("Unknown contentType")

    # --- signature verification ---

    # --- generation time verification ---

if __name__ == "__main__":
    os.system('cls')
    decode_message()
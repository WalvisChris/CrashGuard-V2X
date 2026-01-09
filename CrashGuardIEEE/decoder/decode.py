from CrashGuardIEEE import asn1
from pyasn1.codec.der.decoder import decode as decodeASN1

def decode_unsecure(payload: bytes) -> bytes:
    final_bytes = payload
    return final_bytes

def decode_signed(payload: bytes) -> bytes:
    final_bytes = payload
    return final_bytes

def decode_encrypted(payload: bytes) -> bytes:
    final_bytes = payload
    return final_bytes

def decode_enveloped(payload: bytes) -> bytes:
    final_bytes = payload
    return final_bytes
from CrashGuardIEEE import terminal
from pyasn1.codec.der.decoder import decode as decodeASN1
from pyasn1.type import univ

def decode(payload: bytes) -> bytes:
    top_level, _ = decodeASN1(payload, asn1Spec=univ.Sequence())
    content_type = int(top_level[1])
    
    match content_type:
        case 0:
            return decode_unsecure(payload)
        case 1:
            return decode_signed(payload)
        case 2:
            return decode_encrypted(payload)
        case 3:
            return decode_enveloped(payload)
        case _:
            terminal.text(text=f"Invalid content type: {content_type}!", color="red")
    return None

def decode_unsecure(payload: bytes) -> bytes:
    import CrashGuardIEEE.asn1.unsecure as asn1
    decoded, _ = decodeASN1(payload, asn1Spec=asn1.Ieee1609Dot2Data())
    terminal.printASN1(decoded)

    final_bytes = decoded
    return final_bytes

def decode_signed(payload: bytes) -> bytes:
    import CrashGuardIEEE.asn1.signed as asn1
    decoded, _ = decodeASN1(payload, asn1Spec=asn1.Ieee1609Dot2Data())
    terminal.printASN1(decoded)

    final_bytes = payload
    return final_bytes

def decode_encrypted(payload: bytes) -> bytes:
    import CrashGuardIEEE.asn1.encrypted as asn1  
    decoded, _ = decodeASN1(payload, asn1Spec=asn1.Ieee1609Dot2Data())
    terminal.printASN1(decoded)
    
    final_bytes = payload
    return final_bytes

def decode_enveloped(payload: bytes) -> bytes:
    import CrashGuardIEEE.asn1.enveloped as asn1
    decoded, _ = decodeASN1(payload, asn1Spec=asn1.Ieee1609Dot2Data())
    terminal.printASN1(decoded)
    
    final_bytes = payload
    return final_bytes
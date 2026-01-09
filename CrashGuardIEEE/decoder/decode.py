from CrashGuardIEEE import terminal
from pyasn1.codec.der.decoder import decode as decodeASN1
from pyasn1.type import univ
import time

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

    ieee_content = decoded['content']
    signed_data = ieee_content['signedData']
    tbs_data = signed_data['tbsData']
    header = tbs_data['headerInfo']

    start1 = int(header['generationTime'])
    expire1 = int(header['expiryTime'])
    isHeaderTimeValid, headerTimeDetails = _headerTimeCheck(start=start1, expire=expire1)
    terminal.text(text=f"{isHeaderTimeValid}: {headerTimeDetails}")

    signer_cert = signed_data['signer']['certificate']
    tbs_cert = signer_cert['toBeSignedCert']
    start2 = int(tbs_cert['validityPeriod']['start'])
    duration = int(tbs_cert['validityPeriod']['duration']['hours'])
    isCertTimeValid, certTimeDetails = _certTimeCheck(start=start2, duration=duration)
    terminal.text(text=f"{isCertTimeValid}: {certTimeDetails}")

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

def _headerTimeCheck(start, expire):
    s = int(start)
    e = int(expire)
    n = int(time.time() * 1_000_000) # hetzelfde format

    if n > e:
        return False, "Bericht is verlopen!"
    elif n < s:
        return False, "Bericht uit de toekomst!"
    return True, "Geldig bericht."

def _certTimeCheck(start, duration):
    s = int(start)
    d = int(duration) * 3600 # hours to seconds
    e = s + d
    n = int(time.time())

    if n > e:
        return False, "Certificaat is verlopen!"
    elif n < s:
        return False, "Certificaat uit de toekomst!"
    return True, "Geldig certificaat."

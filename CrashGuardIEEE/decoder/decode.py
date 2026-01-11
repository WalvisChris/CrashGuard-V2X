from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, encode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from CrashGuardIEEE import terminal, PSK
from CrashGuardIEEE.timer import *
from pyasn1.codec.der.decoder import decode as decodeASN1
from pyasn1.codec.der.encoder import encode as encodeASN1
import time

def decode_unsecure(payload: bytes, timer: Timer | None = None) -> bytes:
    import CrashGuardIEEE.asn1.unsecure as asn1
    if timer: timer.startTimer()
    
    decoded, _ = decodeASN1(payload, asn1Spec=asn1.Ieee1609Dot2Data())
    if timer:
        timer.setTimeStamp("ASN1 decoding: Ieee1609Dot2Data")
        timer.stopTimer()
    terminal.printASN1(decoded)

def decode_signed(payload: bytes, timer: Timer | None = None) -> bytes:
    import CrashGuardIEEE.asn1.signed as asn1
    if timer: timer.startTimer()

    decoded, _ = decodeASN1(payload, asn1Spec=asn1.Ieee1609Dot2Data())
    if timer: timer.setTimeStamp("ASN1 decoding: Ieee1609Dot2Data")
    terminal.printASN1(decoded)

    ieee_content = decoded['content']
    signed_data = ieee_content['signedData']
    tbs_data = signed_data['tbsData']
    header = tbs_data['headerInfo']
    if timer: timer.setTimeStamp("ASN1 uitpakken")

    start1 = int(header['generationTime'])
    expire1 = int(header['expiryTime'])
    if timer: timer.setTimeStamp("HeaderInfo metadata opgehaald")
    isHeaderTimeValid, headerTimeDetails = _headerTimeCheck(start=start1, expire=expire1)
    if timer: timer.setTimeStamp("Validation: Header Time")
    terminal.text(text=f"Header Time Validation: {isHeaderTimeValid}: {headerTimeDetails}")

    signer_cert = signed_data['signer']['certificate']
    tbs_cert = signer_cert['toBeSignedCert']
    start2 = int(tbs_cert['validityPeriod']['start'])
    duration = int(tbs_cert['validityPeriod']['duration']['hours'])
    if timer: timer.setTimeStamp("Certificate metadata opgehaald")
    isCertTimeValid, certTimeDetails = _certTimeCheck(start=start2, duration=duration)
    if timer: timer.setTimeStamp("Validation: Certificate Time")
    terminal.text(text=f"Certificate Time Validation: {isCertTimeValid}: {certTimeDetails}")

    verify_key_indicator = tbs_cert['verifyKeyIndicator']
    ecc_point = verify_key_indicator['ecdsaNistP256']['uncompressed']
    x_bytes = bytes(ecc_point['x'])
    y_bytes = bytes(ecc_point['y'])
    x = int.from_bytes(x_bytes, 'big')
    y = int.from_bytes(y_bytes, 'big')
    if timer: timer.setTimeStamp("VerifyKey (X, Y) opgehaald")
    public_numbers = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1())
    cert_public_key = public_numbers.public_key(default_backend())
    if timer: timer.setTimeStamp("Certificate Public Key berekend")
    signature_asn1 = signed_data['signature']['ecdsaNistP256Signature']
    r_bytes = bytes(signature_asn1['r'])
    s_bytes = bytes(signature_asn1['s'])
    if timer: timer.setTimeStamp("Signature (R, S) opgehaald")
    r = int.from_bytes(r_bytes, 'big')
    s = int.from_bytes(s_bytes, 'big')
    signature_der = encode_dss_signature(r, s)
    if timer: timer.setTimeStamp("Signature berekend")
    tbs_der = encodeASN1(tbs_data)
    if timer: timer.setTimeStamp("ASN1 encoding: ToBeSignedData")
    digest = hashes.Hash(hashes.SHA256())
    digest.update(tbs_der)
    hash_value = digest.finalize()

    isSignatureValid, signatureDetails = _verifySignature(key=cert_public_key, bytes=signature_der, hash=hash_value, prehashed=True)
    if timer: timer.setTimeStamp("Validation: SignedData Signature")
    terminal.text(text=f"Signature Validation: {isSignatureValid}: {signatureDetails}")

    cert_signature = bytes(signer_cert['signature'])
    cert_tbs_der = encodeASN1(tbs_cert)
    if timer: timer.setTimeStamp("ASN1 encoding: ToBeSignedCertificate")

    isCertSignatureValid, certSignatureDetails = _verifySignature(key=cert_public_key, bytes=cert_signature, hash=cert_tbs_der)
    if timer: timer.setTimeStamp("Validation: Certificate Signature")
    terminal.text(text=f"Certificate Signature Validation: {isCertSignatureValid}: {certSignatureDetails}")

    if timer: timer.stopTimer()

def decode_encrypted(payload: bytes, timer: Timer | None = None) -> bytes:
    import CrashGuardIEEE.asn1.encrypted as asn1
    if timer: timer.startTimer()

    decoded, _ = decodeASN1(payload, asn1Spec=asn1.Ieee1609Dot2Data())
    if timer: timer.setTimeStamp("ASN1 decoding: Ieee1609Dot2Data")
    terminal.printASN1(decoded)
    
    ieee_content = decoded['content']
    enc_data = ieee_content['encryptedData']
    _me = enc_data['recipients'][0]
    received_pskId = bytes(_me['pskRecipInfo'])
    if timer: timer.setTimeStamp("ASN1 uitpakken")
    digest = hashes.Hash(hashes.SHA256())
    digest.update(PSK)
    expected_pskId = digest.finalize()[:8]
    if timer: timer.setTimeStamp("Expected PskId berekend")

    isPskIdValid, pskIdDetails = _comparePskId(a=received_pskId, b=expected_pskId)
    if timer: timer.setTimeStamp("Validation: PskId")
    terminal.text(text=f"PskId Validation: {isPskIdValid}: {pskIdDetails}")

    ciphertext_struct = (decoded
        ['content']
        ['encryptedData']
        ['ciphertext']
        ['aes128ccm']
    )
    nonce = bytes(ciphertext_struct['nonce'])
    ciphertext = bytes(ciphertext_struct['ccmCiphertext'])
    if timer: timer.setTimeStamp("ASN1 uitpakken: EncryptedData")
    aesccm = AESCCM(PSK)
    if timer: timer.setTimeStamp("AESCCM key berekend")

    isEncryptionValid, encryptionDetails, plaintext = _encCheck(aesccm=aesccm, nonce=nonce, ciphertext=ciphertext)
    if timer: timer.setTimeStamp("Validation: Encryption")
    terminal.text(text=f"Encryption Validation: {isEncryptionValid}: {encryptionDetails}: {plaintext}")

    if timer: timer.stopTimer()

def decode_enveloped(payload: bytes, timer: Timer | None = None) -> bytes:
    import CrashGuardIEEE.asn1.enveloped as asn1
    if timer: timer.startTimer()

    decoded, _ = decodeASN1(payload, asn1Spec=asn1.Ieee1609Dot2Data())
    if timer: timer.setTimeStamp("ASN1 decoding: Ieee1609Dot2Data")
    terminal.printASN1(decoded)

    ieee_content = decoded['content']
    enc_data = ieee_content['encryptedData']
    _me = enc_data['recipients'][0]
    received_pskId = bytes(_me['pskRecipInfo'])
    if timer: timer.setTimeStamp("ASN1 uitpakken")
    digest = hashes.Hash(hashes.SHA256())
    digest.update(PSK)
    expected_pskId = digest.finalize()[:8]
    if timer: timer.setTimeStamp("Expected PskId berekend")

    isPskIdValid, pskIdDetails = _comparePskId(a=received_pskId, b=expected_pskId)
    if timer: timer.setTimeStamp("Validation: PskId")
    terminal.text(text=f"PskId Validation: {isPskIdValid}: {pskIdDetails}")

    ciphertext_struct = (decoded
        ['content']
        ['encryptedData']
        ['ciphertext']
        ['aes128ccm']
    )
    nonce = bytes(ciphertext_struct['nonce'])
    ciphertext = bytes(ciphertext_struct['ccmCiphertext'])
    if timer: timer.setTimeStamp("ASN1 uitpakken: EncryptedData")
    aesccm = AESCCM(PSK)
    if timer: timer.setTimeStamp("AESCCM key berekend")

    isEncryptionValid, encryptionDetails, plaintext = _encCheck(aesccm=aesccm, nonce=nonce, ciphertext=ciphertext)
    if timer: timer.setTimeStamp("Validation: Encryption")
    terminal.text(text=f"Encryption Validation: {isEncryptionValid}: {encryptionDetails}")

    if plaintext:
        signed_data, _ = decodeASN1(plaintext, asn1Spec=asn1.SignedData())
        if timer: timer.setTimeStamp("ASN1 decoding: SignedData")
        terminal.printASN1(signed_data)

        tbs_data = signed_data['tbsData']
        header = tbs_data['headerInfo']
        if timer: timer.setTimeStamp("ASN1 uitpakken")

        start1 = int(header['generationTime'])
        expire1 = int(header['expiryTime'])
        if timer: timer.setTimeStamp("HeaderInfo metadata opgehaald")
        isHeaderTimeValid, headerTimeDetails = _headerTimeCheck(start=start1, expire=expire1)
        if timer: timer.setTimeStamp("Validation: Header Time")
        terminal.text(text=f"Header Time Validation: {isHeaderTimeValid}: {headerTimeDetails}")

        signer_cert = signed_data['signer']['certificate']
        tbs_cert = signer_cert['toBeSignedCert']
        start2 = int(tbs_cert['validityPeriod']['start'])
        duration = int(tbs_cert['validityPeriod']['duration']['hours'])
        if timer: timer.setTimeStamp("Certificate metadata opgehaald")
        isCertTimeValid, certTimeDetails = _certTimeCheck(start=start2, duration=duration)
        if timer: timer.setTimeStamp("Validation: Certificate Time")
        terminal.text(text=f"Certificate Time Validation: {isCertTimeValid}: {certTimeDetails}")

        verify_key_indicator = tbs_cert['verifyKeyIndicator']
        ecc_point = verify_key_indicator['ecdsaNistP256']['uncompressed']
        x_bytes = bytes(ecc_point['x'])
        y_bytes = bytes(ecc_point['y'])
        x = int.from_bytes(x_bytes, 'big')
        y = int.from_bytes(y_bytes, 'big')
        if timer: timer.setTimeStamp("VerifyKey (X, Y) opgehaald")
        public_numbers = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1())
        cert_public_key = public_numbers.public_key(default_backend())
        if timer: timer.setTimeStamp("Certificate Public Key berekend")
        signature_asn1 = signed_data['signature']['ecdsaNistP256Signature']
        r_bytes = bytes(signature_asn1['r'])
        s_bytes = bytes(signature_asn1['s'])
        if timer: timer.setTimeStamp("Signature (R, S) opgehaald")
        r = int.from_bytes(r_bytes, 'big')
        s = int.from_bytes(s_bytes, 'big')
        signature_der = encode_dss_signature(r, s)
        if timer: timer.setTimeStamp("Signature berekend")
        tbs_der = encodeASN1(tbs_data)
        if timer: timer.setTimeStamp("ASN1 encoding: ToBeSignedData")
        digest = hashes.Hash(hashes.SHA256())
        digest.update(tbs_der)
        hash_value = digest.finalize()

        isSignatureValid, signatureDetails = _verifySignature(key=cert_public_key, bytes=signature_der, hash=hash_value, prehashed=True)
        if timer: timer.setTimeStamp("Validation: SignedData Signature")
        terminal.text(text=f"Signature Validation: {isSignatureValid}: {signatureDetails}")

        cert_signature = bytes(signer_cert['signature'])
        cert_tbs_der = encodeASN1(tbs_cert)
        if timer: timer.setTimeStamp("ASN1 encoding: ToBeSignedCertificate")

        isCertSignatureValid, certSignatureDetails = _verifySignature(key=cert_public_key, bytes=cert_signature, hash=cert_tbs_der)
        if timer: timer.setTimeStamp("Validation: Certificate Signature")
        terminal.text(text=f"Certificate Signature Validation: {isCertSignatureValid}: {certSignatureDetails}")

    if timer: timer.stopTimer()

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

def _verifySignature(key, bytes, hash, prehashed=False):
    if prehashed:
        try:
            key.verify(
                bytes,
                hash,
                ec.ECDSA(Prehashed(hashes.SHA256()))
            )
            return True, "Geldige Signature."
        except Exception as e:
            return False, f"Ongeldige Signature: {e}"
    else:
        try:
            key.verify(
                bytes,
                hash,
                ec.ECDSA(hashes.SHA256())
            )
            return True, "Geldige Signature."
        except Exception as e:
            return False, f"Ongeldige Signature: {e}"

def _comparePskId(a, b):
    if a != b:
        return False, "PskId matched niet!"
    else:
        return True, "PskId matched."

def _encCheck(aesccm, nonce, ciphertext):
    try:
        plaintext = aesccm.decrypt(
            nonce=nonce,
            data=ciphertext,
            associated_data=None
        )
        return True, f"Encryptie geslaagd.", plaintext
    except:
        return False, "Encrypie mislukt!", None
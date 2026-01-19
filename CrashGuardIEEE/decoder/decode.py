from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, encode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from CrashGuardIEEE import terminal, PSK, ROOT_CA_PUBLIC_KEY
from CrashGuardIEEE.timer import *
from pyasn1.codec.der.decoder import decode as decodeASN1
from pyasn1.codec.der.encoder import encode as encodeASN1
import time

def decode_unsecure(payload: bytes, timer: Timer | None = None) -> bytes:
    import CrashGuardIEEE.asn1.unsecure as asn1
    if timer: timer.startTimer()
    
    try:
        decoded, _ = decodeASN1(payload, asn1Spec=asn1.Ieee1609Dot2Data())
        if timer:
            timer.setTimeStamp("ASN1 decoding: Ieee1609Dot2Data")
            timer.stopTimer()

        terminal.printASN1(decoded)
    
    except:
        terminal.text("Content type did not match the ASN.1 structure!", color="red")

def decode_signed(payload: bytes, timer: Timer | None = None) -> bytes:
    import CrashGuardIEEE.asn1.signed as asn1
    isHeaderTimeValid = None
    isCertTimeValid = None
    isSignatureValid= None
    isCertSignatureValid = None
    if timer: timer.startTimer()

    try:
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
        isHeaderTimeValid = _headerTimeCheck(start=start1, expire=expire1)
        if timer: timer.setTimeStamp("Validation: Header Time")

        signer_cert = signed_data['signer']['certificate']
        tbs_cert = signer_cert['toBeSignedCert']
        start2 = int(tbs_cert['validityPeriod']['start'])
        duration = int(tbs_cert['validityPeriod']['duration']['hours'])
        if timer: timer.setTimeStamp("Certificate metadata opgehaald")
        isCertTimeValid = _certTimeCheck(start=start2, duration=duration)
        if timer: timer.setTimeStamp("Validation: Certificate Time")

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

        isSignatureValid = _verifyMessageSignature(key=cert_public_key, signature=signature_der, data=tbs_der)
        if timer: timer.setTimeStamp("Validation: SignedData Signature")

        cert_signature = bytes(signer_cert['signature'])
        cert_tbs_der = encodeASN1(tbs_cert)
        if timer: timer.setTimeStamp("ASN1 encoding: ToBeSignedCertificate")

        isCertSignatureValid = _verifyCertificateSignature(key=ROOT_CA_PUBLIC_KEY, signature=cert_signature, data=cert_tbs_der)
        if timer: timer.setTimeStamp("Validation: Certificate Signature")

        if timer: timer.stopTimer()
        terminal.logFase4(headerTime=isHeaderTimeValid, certTime=isCertTimeValid, sig=isSignatureValid, certSig=isCertSignatureValid)
    
    except:
        terminal.text("Content type did not match the ASN.1 structure!", color="red")

def decode_encrypted(payload: bytes, timer: Timer | None = None) -> bytes:
    import CrashGuardIEEE.asn1.encrypted as asn1
    isPskIdValid = None
    isEncryptionValid = None
    if timer: timer.startTimer()

    try:
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

        isPskIdValid = _comparePskId(a=received_pskId, b=expected_pskId)
        if timer: timer.setTimeStamp("Validation: PskId")

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

        isEncryptionValid, plaintext = _encCheck(aesccm=aesccm, nonce=nonce, ciphertext=ciphertext)
        if timer: timer.setTimeStamp(f"Validation: Encryption")
        terminal.text(f"Decrypted Payload: {plaintext}")

        if timer: timer.stopTimer()
        terminal.logFase4(pskId=isPskIdValid, enc=isEncryptionValid)
    
    except:
        terminal.text("Content type did not match the ASN.1 structure!", color="red")

def decode_enveloped(payload: bytes, timer: Timer | None = None) -> bytes:
    import CrashGuardIEEE.asn1.enveloped as asn1
    isPskIdValid  = None
    isEncryptionValid = None
    isHeaderTimeValid = None
    isCertTimeValid = None
    isSignatureValid = None
    isCertSignatureValid = None
    if timer: timer.startTimer()

    try:
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

        isPskIdValid = _comparePskId(a=received_pskId, b=expected_pskId)
        if timer: timer.setTimeStamp("Validation: PskId")

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

        isEncryptionValid, plaintext = _encCheck(aesccm=aesccm, nonce=nonce, ciphertext=ciphertext)
        if timer: timer.setTimeStamp("Validation: Encryption")

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
            isHeaderTimeValid = _headerTimeCheck(start=start1, expire=expire1)
            if timer: timer.setTimeStamp("Validation: Header Time")

            signer_cert = signed_data['signer']['certificate']
            tbs_cert = signer_cert['toBeSignedCert']
            start2 = int(tbs_cert['validityPeriod']['start'])
            duration = int(tbs_cert['validityPeriod']['duration']['hours'])
            if timer: timer.setTimeStamp("Certificate metadata opgehaald")
            isCertTimeValid = _certTimeCheck(start=start2, duration=duration)
            if timer: timer.setTimeStamp("Validation: Certificate Time")

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

            isSignatureValid = _verifyMessageSignature(key=cert_public_key, signature=signature_der, data=tbs_der)
            if timer: timer.setTimeStamp("Validation: SignedData Signature")

            cert_signature = bytes(signer_cert['signature'])
            cert_tbs_der = encodeASN1(tbs_cert)
            if timer: timer.setTimeStamp("ASN1 encoding: ToBeSignedCertificate")

            isCertSignatureValid = _verifyCertificateSignature(key=ROOT_CA_PUBLIC_KEY, signature=cert_signature, data=cert_tbs_der)
            if timer: timer.setTimeStamp("Validation: Certificate Signature")

        if timer: timer.stopTimer()
        terminal.logFase4(headerTime=isHeaderTimeValid, certTime=isCertTimeValid, sig=isSignatureValid, certSig=isCertSignatureValid, pskId=isPskIdValid, enc=isEncryptionValid)
    
    except:
        terminal.text("Content type did not match the ASN.1 structure!", color="red")

def _headerTimeCheck(start, expire):
    s = int(start)
    e = int(expire)
    n = int(time.time() * 1_000_000) # hetzelfde format

    if n > e:
        return ["Bericht Tijdcontrole", False, "Bericht is verlopen!"]
    elif n < s:
        return ["Bericht Tijdcontrole", False, "Bericht uit de toekomst!"]
    return ["Bericht Tijdcontrole", True, "Geldig bericht."]

def _certTimeCheck(start, duration):
    s = int(start)
    d = int(duration) * 3600 # hours to seconds
    e = s + d
    n = int(time.time())

    if n > e:
        return ["Certifcaat Tijcontrole", False, "Certificaat is verlopen!"]
    elif n < s:
        return ["Certificaat Tijdcontrole", False, "Certificaat uit de toekomst!"]
    return ["Certificaat Tijdcontrole", True, "Geldig certificaat."]

def _verifyMessageSignature(key, signature, data):
    try:
        key.verify(
            signature,
            data,
            ec.ECDSA(hashes.SHA256())
        )
        return ["Msg Signature Validatie", True, "Geldige Signature."]
    except Exception as e:
        return ["Msg Signature Validatie", False, f"Ongeldige Signature: {e}"]

def _verifyCertificateSignature(key, signature, data):
    try:
        key.verify(
            signature,
            data,
            ec.ECDSA(hashes.SHA256())
        )
        return ["Cert Signature Validatie", True, "Geldige Signature."]
    except Exception as e:
        return ["Cert Signature Validatie", False, f"Ongeldige Signature: {e}"] 

def _comparePskId(a, b):
    if a != b:
        return ["PskId Validatie", False, "PskId matched niet!"]
    else:
        return ["PskId Validatie", True, "PskId matched."]

def _encCheck(aesccm, nonce, ciphertext):
    try:
        plaintext = aesccm.decrypt(
            nonce=nonce,
            data=ciphertext,
            associated_data=None
        )
        return ["Encryptie", True, f"Encryptie geslaagd."], plaintext
    except:
        return ["Encrytpie", False, "Encrypie mislukt!"], None

def get_decoded_unsecure(payload: bytes):
    import CrashGuardIEEE.asn1.unsecure as asn1    
    try:
        # Uitpakken
        decoded, _ = decodeASN1(payload, asn1Spec=asn1.Ieee1609Dot2Data())
        
        # Presentatie
        payload = decoded['content']['unsecureData']
        result = { "payload": str(payload) }
        return result
    except:
        terminal.text("Content type did not match the ASN.1 structure! UNSECURE", color="red")
    return None

def get_decoded_signed(payload: bytes):
    import CrashGuardIEEE.asn1.signed as asn1
    try:
        decoded, _ = decodeASN1(payload, asn1Spec=asn1.Ieee1609Dot2Data())
        
        # Uitpakken
        signed_data = decoded['content']['signedData']
        signer_cert = signed_data['signer']['certificate']
        tbs_data = signed_data['tbsData']
        header = tbs_data['headerInfo']
        start1 = int(header['generationTime'])
        expire1 = int(header['expiryTime'])
        tbs_cert = signer_cert['toBeSignedCert']
        start2 = int(tbs_cert['validityPeriod']['start'])
        duration = int(tbs_cert['validityPeriod']['duration']['hours'])
        
        signature_asn1 = signed_data['signature']['ecdsaNistP256Signature']
        r_bytes = bytes(signature_asn1['r'])
        s_bytes = bytes(signature_asn1['s'])
        r = int.from_bytes(r_bytes, 'big')
        s = int.from_bytes(s_bytes, 'big')
        signature_der = encode_dss_signature(r, s)
        tbs_der = encodeASN1(tbs_data)
        
        cert_signature = bytes(signer_cert['signature'])
        cert_tbs_der = encodeASN1(tbs_cert)
        verify_key_indicator = tbs_cert['verifyKeyIndicator']
        ecc_point = verify_key_indicator['ecdsaNistP256']['uncompressed']
        x_bytes = bytes(ecc_point['x'])
        y_bytes = bytes(ecc_point['y'])
        x = int.from_bytes(x_bytes, 'big')
        y = int.from_bytes(y_bytes, 'big')
        public_numbers = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1())
        cert_public_key = public_numbers.public_key(default_backend())

        # Validation
        v1 = _headerTimeCheck(start=start1, expire=expire1)
        v2 = _certTimeCheck(start=start2, duration=duration)
        v3 = _verifyMessageSignature(key=cert_public_key, signature=signature_der, data=tbs_der)
        v4 = _verifyCertificateSignature(key=ROOT_CA_PUBLIC_KEY, signature=cert_signature, data=cert_tbs_der)

        # Presentation
        payload = tbs_data['payload']['data']
        psid = header['psid']
        generation = header['generationTime']
        signer = tbs_cert['id']['name']
        result = {
            "payload": str(payload),
            "psid": str(psid),
            "generation time": str(generation),
            "signer name": str(signer),
            "validation": {
                "HeaderTime": v1[0],
                "CertificateTime": v2[0],
                "MessageSignature": v3[0],
                "CertificateSignature": v4[0]
            }
        }
        return result
    except:
        terminal.text("Content type did not match the ASN.1 structure! SIGNED", color="red")
    return None

def get_decoded_encrypted(payload: bytes):
    import CrashGuardIEEE.asn1.encrypted as asn1
    try:
        # Uitpakken
        decoded, _ = decodeASN1(payload, asn1Spec=asn1.Ieee1609Dot2Data())
        enc_data = decoded['content']['encryptedData']
        _me = enc_data['recipients'][0]
        received_pskId = bytes(_me['pskRecipInfo'])
        digest = hashes.Hash(hashes.SHA256())
        digest.update(PSK)
        expected_pskId = digest.finalize()[:8]
        ciphertext_struct = (decoded
            ['content']
            ['encryptedData']
            ['ciphertext']
            ['aes128ccm']
        )
        nonce = bytes(ciphertext_struct['nonce'])
        ciphertext = bytes(ciphertext_struct['ccmCiphertext'])
        aesccm = AESCCM(PSK)

        # Validatie
        v1 = _comparePskId(a=received_pskId, b=expected_pskId)
        v2, payload = _encCheck(aesccm=aesccm, nonce=nonce, ciphertext=ciphertext)

        # Presentatie
        result = {
            "pskId": str(received_pskId),
            "nonce": str(nonce),
            "ciphertext": str(ciphertext),
            "validation": {
                "PskId": v1[0],
                "Encryptie": v2[0],
                "Payload": payload
            }
        }
        return result
    except Exception as e:
        terminal.text(f"Content type did not match the ASN.1 structure! ENCRYPTED\n{e}", color="red")
    return None

def get_decoded_enveloped(payload: bytes):
    import CrashGuardIEEE.asn1.enveloped as asn1
    try:
        # Uitpakken
        decoded, _ = decodeASN1(payload, asn1Spec=asn1.Ieee1609Dot2Data())
        enc_data = decoded['content']['encryptedData']
        _me = enc_data['recipients'][0]
        received_pskId = bytes(_me['pskRecipInfo'])
        digest = hashes.Hash(hashes.SHA256())
        digest.update(PSK)
        expected_pskId = digest.finalize()[:8]
        ciphertext_struct = (decoded
            ['content']
            ['encryptedData']
            ['ciphertext']
            ['aes128ccm']
        )
        nonce = bytes(ciphertext_struct['nonce'])
        ciphertext = bytes(ciphertext_struct['ccmCiphertext'])
        aesccm = AESCCM(PSK)

        # Validatie
        v1 = _comparePskId(a=received_pskId, b=expected_pskId)
        v2, plaintext = _encCheck(aesccm=aesccm, nonce=nonce, ciphertext=ciphertext)

        if plaintext:
            signed_data, _ = decodeASN1(plaintext, asn1Spec=asn1.SignedData())

            # Uitpakken
            signer_cert = signed_data['signer']['certificate']
            tbs_data = signed_data['tbsData']
            header = tbs_data['headerInfo']
            start1 = int(header['generationTime'])
            expire1 = int(header['expiryTime'])
            tbs_cert = signer_cert['toBeSignedCert']
            start2 = int(tbs_cert['validityPeriod']['start'])
            duration = int(tbs_cert['validityPeriod']['duration']['hours'])
            
            signature_asn1 = signed_data['signature']['ecdsaNistP256Signature']
            r_bytes = bytes(signature_asn1['r'])
            s_bytes = bytes(signature_asn1['s'])
            r = int.from_bytes(r_bytes, 'big')
            s = int.from_bytes(s_bytes, 'big')
            signature_der = encode_dss_signature(r, s)
            tbs_der = encodeASN1(tbs_data)
            
            cert_signature = bytes(signer_cert['signature'])
            cert_tbs_der = encodeASN1(tbs_cert)
            verify_key_indicator = tbs_cert['verifyKeyIndicator']
            ecc_point = verify_key_indicator['ecdsaNistP256']['uncompressed']
            x_bytes = bytes(ecc_point['x'])
            y_bytes = bytes(ecc_point['y'])
            x = int.from_bytes(x_bytes, 'big')
            y = int.from_bytes(y_bytes, 'big')
            public_numbers = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1())
            cert_public_key = public_numbers.public_key(default_backend())

            # Validation
            v3 = _headerTimeCheck(start=start1, expire=expire1)
            v4 = _certTimeCheck(start=start2, duration=duration)
            v5 = _verifyMessageSignature(key=cert_public_key, signature=signature_der, data=tbs_der)
            v6 = _verifyCertificateSignature(key=ROOT_CA_PUBLIC_KEY, signature=cert_signature, data=cert_tbs_der)

            # Presentation
            payload = tbs_data['payload']['data']
            psid = header['psid']
            generation = header['generationTime']
            signer = tbs_cert['id']['name']

        # Presentatie
        result = {
            "pskId": str(received_pskId),
            "nonce": str(nonce),
            "ciphertext": str(ciphertext),
            "psid": str(psid),
            "generation time": str(generation),
            "signer name": str(signer),
            "validation": {
                "PskId": v1[0],
                "Encryptie": v2[0],
                "HeaderTime": v3[0],
                "CertificateTime": v4[0],
                "MessageSignature": v5[0],
                "CertificateSignature": v6[0]
            }
        }
        return result
    except Exception as e:
        terminal.text(f"Content type did not match the ASN.1 structure! ENCRYPTED\n{e}", color="red")
    return None
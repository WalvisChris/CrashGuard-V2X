"""Dit script bevat alle code voor het uitpakken/decoding van het IEEE bericht bij de ontvanger/pijlwagen"""

# Allereerst importeren we de nodige open source libraries en alle functies en waardes van CrashGuardIEEE
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, encode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.backends import default_backend
from CrashGuardIEEE import terminal, PSK, ROOT_CA_PUBLIC_KEY, latest_protocol_version
from CrashGuardIEEE.timer import *
from pyasn1.codec.der.decoder import decode as decodeASN1
from pyasn1.codec.der.encoder import encode as encodeASN1
import time

"""de functie 'decode_unsecure' bevat alle code voor het uitpakken van een unsecure bericht"""
def decode_unsecure(payload: bytes, timer: Timer | None = None) -> bytes:
    # eerst importeren we de juist ASN.1 structuren die nodig zijn voor unsecure data
    import CrashGuardIEEE.asn1.unsecure as asn1
    if timer: timer.startTimer()
    
    try:
        decoded, _ = decodeASN1(payload, asn1Spec=asn1.Ieee1609Dot2Data()) # het bericht wordt volgens de unsecure ASN.1 structuur gedecode
        if timer:
            timer.setTimeStamp("ASN1 decoding: Ieee1609Dot2Data")
            timer.stopTimer()

        # Alle belangrijke velden worden uitgelezen vanaf de bovenste structuur
        protocol_version = decoded['protocolVersion']
        protocol_version = int(protocol_version)
        if protocol_version < latest_protocol_version:
            terminal.text(f"Message protocol version ({protocol_version}) is outdated. Latest version is {latest_protocol_version}", color="red")
        
        # het bericht wordt in kleur in de terminal weergegeven
        terminal.printASN1(decoded)
    
    except:
        terminal.text("Content type did not match the ASN.1 structure!", color="red") # error als de decoding niet lukt

"""de functie 'decode_signed' bevat alle code voor het uitpakken van een signed bericht"""
def decode_signed(payload: bytes, timer: Timer | None = None) -> bytes:
    # eerst importeren we de juist ASN.1 structuren die nodig zijn voor signed data
    import CrashGuardIEEE.asn1.signed as asn1

    # validaties worden vooraf gedefinieerd
    isHeaderTimeValid = None
    isCertTimeValid = None
    isSignatureValid= None
    isCertSignatureValid = None

    if timer: timer.startTimer()

    try:
        decoded, _ = decodeASN1(payload, asn1Spec=asn1.Ieee1609Dot2Data()) # het bericht wordt volgens de signed ASN.1 structuur gedecode
        if timer: timer.setTimeStamp("ASN1 decoding: Ieee1609Dot2Data")
        
        # Alle belangrijke velden worden uitgelezen vanaf de bovenste structuur
        protocol_version = decoded['protocolVersion']
        protocol_version = int(protocol_version)
        if protocol_version < latest_protocol_version: # protocol versie wordt gevalideerd
            terminal.text(f"Message protocol version ({protocol_version}) is outdated. Latest version is {latest_protocol_version}", color="red")
        
        # het bericht wordt in kleur in de terminal weergegeven
        terminal.printASN1(decoded)

        # Alle belangrijke velden worden uitgelezen vanaf de bovenste structuur
        ieee_content = decoded['content']
        signed_data = ieee_content['signedData']
        tbs_data = signed_data['tbsData']
        header = tbs_data['headerInfo']
        if timer: timer.setTimeStamp("ASN1 uitpakken")

        # benodigde velden om HeaderTimeValidatie te doen worden uit de Header uitgelezen
        start1 = int(header['generationTime'])
        expire1 = int(header['expiryTime'])
        if timer: timer.setTimeStamp("HeaderInfo metadata opgehaald")
        isHeaderTimeValid = _headerTimeCheck(start=start1, expire=expire1)
        if timer: timer.setTimeStamp("Validation: Header Time")

        # benodigde velden om CertificateTimeCheck te doen worden uit de Certificate uitgelezen
        signer_cert = signed_data['signer']['certificate']
        tbs_cert = signer_cert['toBeSignedCert']
        start2 = int(tbs_cert['validityPeriod']['start'])
        duration = int(tbs_cert['validityPeriod']['duration']['hours'])
        if timer: timer.setTimeStamp("Certificate metadata opgehaald")
        isCertTimeValid = _certTimeCheck(start=start2, duration=duration)
        if timer: timer.setTimeStamp("Validation: Certificate Time")

        # benodigde velden om MessageSignatureVerification te doen worden uit de ToBeSignedCertificate uitgelezen
        verify_key_indicator = tbs_cert['verifyKeyIndicator']
        ecc_point = verify_key_indicator['ecdsaNistP256']['uncompressed']
        x_bytes = bytes(ecc_point['x']) # x positie van de public numbers wordt uitgelezen
        y_bytes = bytes(ecc_point['y']) # y positie van de public numbers wordt uitgelezen
        x = int.from_bytes(x_bytes, 'big') # x wordt omgezet in integer
        y = int.from_bytes(y_bytes, 'big') # y wordt omgezet in integer
        if timer: timer.setTimeStamp("VerifyKey (X, Y) opgehaald")
        public_numbers = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()) # public numbers worden berekend op basis van X en Y
        cert_public_key = public_numbers.public_key(default_backend()) # public key wordt berekend op basis van public numbers
        if timer: timer.setTimeStamp("Certificate Public Key berekend")
        signature_asn1 = signed_data['signature']['ecdsaNistP256Signature']
        r_bytes = bytes(signature_asn1['r']) # R bytes van signature wordt uitgelezen 
        s_bytes = bytes(signature_asn1['s']) # S bytes van signature wordt uitgelezen
        if timer: timer.setTimeStamp("Signature (R, S) opgehaald")
        r = int.from_bytes(r_bytes, 'big') # R wordt omgezet naar integer
        s = int.from_bytes(s_bytes, 'big') # S wordt omgezet naar integer
        signature_der = encode_dss_signature(r, s) # signature wordt berekend op basis van R en S
        if timer: timer.setTimeStamp("Signature berekend")
        tbs_der = encodeASN1(tbs_data) # ASN.1 encoding bij ToBeSignedData voordat hij gevalideerd wordt 
        if timer: timer.setTimeStamp("ASN1 encoding: ToBeSignedData")

        isSignatureValid = _verifyMessageSignature(key=cert_public_key, signature=signature_der, data=tbs_der) # Message signature validatie
        if timer: timer.setTimeStamp("Validation: SignedData Signature")

        cert_signature = bytes(signer_cert['signature'])
        cert_tbs_der = encodeASN1(tbs_cert) # ASN.1 decoding bij ToBeSignedCertificate voordat hij gevalideerd wordt
        if timer: timer.setTimeStamp("ASN1 encoding: ToBeSignedCertificate")

        isCertSignatureValid = _verifyCertificateSignature(key=ROOT_CA_PUBLIC_KEY, signature=cert_signature, data=cert_tbs_der) # Certificate signature validatie
        if timer: timer.setTimeStamp("Validation: Certificate Signature")

        if timer: timer.stopTimer()
        # log validatie in terminal
        terminal.logFase4(headerTime=isHeaderTimeValid, certTime=isCertTimeValid, sig=isSignatureValid, certSig=isCertSignatureValid)
    
    except:
        terminal.text("Content type did not match the ASN.1 structure!", color="red") # error als de decoding niet lukt

"""de functie 'decode_encrypted' bevat alle code voor het uitpakken van een encrypted bericht"""
def decode_encrypted(payload: bytes, timer: Timer | None = None) -> bytes:
    # eerst importeren we de juist ASN.1 structuren die nodig zijn voor encrypted data
    import CrashGuardIEEE.asn1.encrypted as asn1
    
    # validaties worden vooraf gedefinieerd
    isPskIdValid = None
    isEncryptionValid = None

    if timer: timer.startTimer()

    try:
        decoded, _ = decodeASN1(payload, asn1Spec=asn1.Ieee1609Dot2Data()) # het bericht wordt volgens de encrypted ASN.1 structuur gedecode
        if timer: timer.setTimeStamp("ASN1 decoding: Ieee1609Dot2Data")
        
        # Alle belangrijke velden worden uitgelezen vanaf de bovenste structuur
        protocol_version = decoded['protocolVersion']
        protocol_version = int(protocol_version)
        if protocol_version < latest_protocol_version: # protocol versie wordt gevalideerd
            terminal.text(f"Message protocol version ({protocol_version}) is outdated. Latest version is {latest_protocol_version}", color="red")
        
        # het bericht wordt in kleur in de terminal weergegeven
        terminal.printASN1(decoded)
        
        # Alle belangrijke velden worden uitgelezen vanaf de bovenste structuur
        ieee_content = decoded['content']
        enc_data = ieee_content['encryptedData']
        _me = enc_data['recipients'][0]
        received_pskId = bytes(_me['pskRecipInfo']) # ontvangen pre-shared key wordt uitgelezen vanuit RecipientInfo
        if timer: timer.setTimeStamp("ASN1 uitpakken")
        # PskId wordt berekend op basis van pre-shared key
        digest = hashes.Hash(hashes.SHA256())
        digest.update(PSK)
        expected_pskId = digest.finalize()[:8]
        if timer: timer.setTimeStamp("Expected PskId berekend")

        isPskIdValid = _comparePskId(a=received_pskId, b=expected_pskId) # PskId validatie
        if timer: timer.setTimeStamp("Validation: PskId")

        # ciphertext_struct wordt uitgelezen
        ciphertext_struct = (decoded
            ['content']
            ['encryptedData']
            ['ciphertext']
            ['aes128ccm']
        )
        nonce = bytes(ciphertext_struct['nonce']) # nonce wordt uitgelezen vanuit de ciphertext_struct
        ciphertext = bytes(ciphertext_struct['ccmCiphertext']) # ciphertext wordt uitgelezen vanuit de ciphertext_struct
        if timer: timer.setTimeStamp("ASN1 uitpakken: EncryptedData")
        aesccm = AESCCM(PSK) # AESCCM key wordt berekend op basis van pre-shared key
        if timer: timer.setTimeStamp("AESCCM key berekend")

        isEncryptionValid, plaintext = _encCheck(aesccm=aesccm, nonce=nonce, ciphertext=ciphertext) # Encryptie/decryptie validatie
        if timer: timer.setTimeStamp(f"Validation: Encryption")
        terminal.text(f"Decrypted Payload: {plaintext}")

        if timer: timer.stopTimer()
        # log validatie in terminal
        terminal.logFase4(pskId=isPskIdValid, enc=isEncryptionValid)
    
    except:
        terminal.text("Content type did not match the ASN.1 structure!", color="red") # error als de decoding niet lukt

"""de functie 'decode_enveloped' bevat alle code voor het uitpakken van een enveloped bericht"""
def decode_enveloped(payload: bytes, timer: Timer | None = None) -> bytes:
    # eerst importeren we de juist ASN.1 structuren die nodig zijn voor enveloped data
    import CrashGuardIEEE.asn1.enveloped as asn1
    
    # validaties worden vooraf gedefinieerd
    isPskIdValid  = None
    isEncryptionValid = None
    isHeaderTimeValid = None
    isCertTimeValid = None
    isSignatureValid = None
    isCertSignatureValid = None

    if timer: timer.startTimer()

    try:
        decoded, _ = decodeASN1(payload, asn1Spec=asn1.Ieee1609Dot2Data()) # het bericht wordt volgens de enveloped ASN.1 structuur gedecode
        if timer: timer.setTimeStamp("ASN1 decoding: Ieee1609Dot2Data")
        
        # Alle belangrijke velden worden uitgelezen vanaf de bovenste structuur
        protocol_version = decoded['protocolVersion']
        protocol_version = int(protocol_version)
        if protocol_version < latest_protocol_version:
            terminal.text(f"Message protocol version ({protocol_version}) is outdated. Latest version is {latest_protocol_version}", color="red")
        
        # het bericht wordt in kleur in de terminal weergegeven
        terminal.printASN1(decoded)

        # Alle belangrijke velden worden uitgelezen vanaf de bovenste structuur
        ieee_content = decoded['content']
        enc_data = ieee_content['encryptedData']
        _me = enc_data['recipients'][0]
        received_pskId = bytes(_me['pskRecipInfo']) # ontvangen pre-shared key wordt uitgelezen vanuit RecipientInfo
        if timer: timer.setTimeStamp("ASN1 uitpakken")
        # PskId wordt berekend op basis van pre-shared key
        digest = hashes.Hash(hashes.SHA256())
        digest.update(PSK)
        expected_pskId = digest.finalize()[:8]
        if timer: timer.setTimeStamp("Expected PskId berekend")

        isPskIdValid = _comparePskId(a=received_pskId, b=expected_pskId) # PskId validatie
        if timer: timer.setTimeStamp("Validation: PskId")

        # ciphertext_struct wordt uitgelezen
        ciphertext_struct = (decoded
            ['content']
            ['encryptedData']
            ['ciphertext']
            ['aes128ccm']
        )
        nonce = bytes(ciphertext_struct['nonce']) # nonce wordt uitgelezen vanuit de ciphertext_struct
        ciphertext = bytes(ciphertext_struct['ccmCiphertext']) # ciphertext wordt uitgelezen vanuit de ciphertext_struct
        if timer: timer.setTimeStamp("ASN1 uitpakken: EncryptedData")
        aesccm = AESCCM(PSK) # AESCCM key wordt berekend op basis van pre-shared key
        if timer: timer.setTimeStamp("AESCCM key berekend")

        isEncryptionValid, plaintext = _encCheck(aesccm=aesccm, nonce=nonce, ciphertext=ciphertext) # Encryptie/decryptie validatie
        if timer: timer.setTimeStamp("Validation: Encryption")

        # als de decryptie is gelukt is de SignedData structuur uit te lezen en kan de validatie hiervan beginnen...
        if plaintext:
            signed_data, _ = decodeASN1(plaintext, asn1Spec=asn1.SignedData()) # het bericht wordt volgens de signed ASN.1 structuur gedecode
            if timer: timer.setTimeStamp("ASN1 decoding: SignedData")
            
            # het bericht wordt in kleur in de terminal weergegeven
            terminal.printASN1(signed_data)

            # Alle belangrijke velden worden uitgelezen vanaf de bovenste structuur
            tbs_data = signed_data['tbsData']
            header = tbs_data['headerInfo']
            if timer: timer.setTimeStamp("ASN1 uitpakken")

            # benodigde velden om HeaderTimeValidatie te doen worden uit de Header uitgelezen
            start1 = int(header['generationTime'])
            expire1 = int(header['expiryTime'])
            if timer: timer.setTimeStamp("HeaderInfo metadata opgehaald")
            isHeaderTimeValid = _headerTimeCheck(start=start1, expire=expire1)
            if timer: timer.setTimeStamp("Validation: Header Time")

            # benodigde velden om CertificateTimeCheck te doen worden uit de Certificate uitgelezen
            signer_cert = signed_data['signer']['certificate']
            tbs_cert = signer_cert['toBeSignedCert']
            start2 = int(tbs_cert['validityPeriod']['start'])
            duration = int(tbs_cert['validityPeriod']['duration']['hours'])
            if timer: timer.setTimeStamp("Certificate metadata opgehaald")
            isCertTimeValid = _certTimeCheck(start=start2, duration=duration)
            if timer: timer.setTimeStamp("Validation: Certificate Time")

            # benodigde velden om MessageSignatureVerification te doen worden uit de ToBeSignedCertificate uitgelezen
            verify_key_indicator = tbs_cert['verifyKeyIndicator']
            ecc_point = verify_key_indicator['ecdsaNistP256']['uncompressed']
            x_bytes = bytes(ecc_point['x']) # x positie van de public numbers wordt uitgelezen
            y_bytes = bytes(ecc_point['y']) # y positie van de public numbers wordt uitgelezen
            x = int.from_bytes(x_bytes, 'big') # x wordt omgezet in integer
            y = int.from_bytes(y_bytes, 'big') # y wordt omgezet in integer
            if timer: timer.setTimeStamp("VerifyKey (X, Y) opgehaald")
            public_numbers = ec.EllipticCurvePublicNumbers(x, y, ec.SECP256R1()) # public numbers worden berekend op basis van X en Y
            cert_public_key = public_numbers.public_key(default_backend()) # public key wordt berekend op basis van public numbers
            if timer: timer.setTimeStamp("Certificate Public Key berekend")
            signature_asn1 = signed_data['signature']['ecdsaNistP256Signature']
            r_bytes = bytes(signature_asn1['r']) # R bytes van signature wordt uitgelezen 
            s_bytes = bytes(signature_asn1['s']) # S bytes van signature wordt uitgelezen 
            if timer: timer.setTimeStamp("Signature (R, S) opgehaald")
            r = int.from_bytes(r_bytes, 'big') # R wordt omgezet naar integer
            s = int.from_bytes(s_bytes, 'big') # S wordt omgezet naar integer
            signature_der = encode_dss_signature(r, s) # signature wordt berekend op basis van R en S
            if timer: timer.setTimeStamp("Signature berekend")
            tbs_der = encodeASN1(tbs_data) # ASN.1 encoding bij ToBeSignedData voordat hij gevalideerd wordt 
            if timer: timer.setTimeStamp("ASN1 encoding: ToBeSignedData")

            isSignatureValid = _verifyMessageSignature(key=cert_public_key, signature=signature_der, data=tbs_der) # Message signature validatie
            if timer: timer.setTimeStamp("Validation: SignedData Signature")

            cert_signature = bytes(signer_cert['signature'])
            cert_tbs_der = encodeASN1(tbs_cert) # ASN.1 decoding bij ToBeSignedCertificate voordat hij gevalideerd wordt
            if timer: timer.setTimeStamp("ASN1 encoding: ToBeSignedCertificate")

            isCertSignatureValid = _verifyCertificateSignature(key=ROOT_CA_PUBLIC_KEY, signature=cert_signature, data=cert_tbs_der) # Certificate signature validatie
            if timer: timer.setTimeStamp("Validation: Certificate Signature")

        if timer: timer.stopTimer()
        # log validatie in terminal
        terminal.logFase4(headerTime=isHeaderTimeValid, certTime=isCertTimeValid, sig=isSignatureValid, certSig=isCertSignatureValid, pskId=isPskIdValid, enc=isEncryptionValid)
    
    except:
        terminal.text("Content type did not match the ASN.1 structure!", color="red") # error als de decoding niet lukt

"""de functie '_headerTimeCheck' controlleerd of de huidige tijd tussen de generation time en expiry time valt"""
def _headerTimeCheck(start, expire):
    s = int(start) # start moment
    e = int(expire) # expire moment
    n = int(time.time() * 1_000_000) # 'nu' moment omzetten naar het juist formate

    if n > e:
        return ["Bericht Tijdcontrole", False, "Bericht is verlopen!"]
    elif n < s:
        return ["Bericht Tijdcontrole", False, "Bericht uit de toekomst!"]
    return ["Bericht Tijdcontrole", True, "Geldig bericht."]

"""de functie '_certTimeCheck' controlleerd of het certificaat als is uitgegeven en of deze nog niet is verlopen"""
def _certTimeCheck(start, duration):
    s = int(start) # start moment
    d = int(duration) * 3600 # duration omzetten naar seconden omdat deze bij de encode als hours gedefinieerd wordt
    e = s + d # expire moment = start + duration
    n = int(time.time()) # 'nu' moment

    if n > e:
        return ["Certifcaat Tijcontrole", False, "Certificaat is verlopen!"]
    elif n < s:
        return ["Certificaat Tijdcontrole", False, "Certificaat uit de toekomst!"]
    return ["Certificaat Tijdcontrole", True, "Geldig certificaat."]

"""de functie '_verifyMessageSignature' valideert de signature met de public key"""
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

"""de functie '_verifyCertificateSignature' valideert de signature met de public key"""
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

"""de functie '_comparePskId' vergelijkt de ontvangen PskId met de verwachtte PskId"""
def _comparePskId(a, b):
    if a != b:
        return ["PskId Validatie", False, "PskId matched niet!"]
    else:
        return ["PskId Validatie", True, "PskId matched."]

"""de functie '_encCheck' probeert de ciphertext met de Nonce en AESCCM key te decrypten"""
def _encCheck(aesccm, nonce, ciphertext):
    try:
        plaintext = aesccm.decrypt(
            nonce=nonce,
            data=ciphertext,
            associated_data=None
        )
        return ["Encryptie", True, f"Encryptie geslaagd."], plaintext
    except:
        return ["Encryptie", False, "Encryptie mislukt!"], None

"""de functie 'get_decoded_unsecure' doet hetzelfde als decode_unsecure, alleen geeft hij de waarde terug als bytes"""
def get_decoded_unsecure(payload: bytes):
    import CrashGuardIEEE.asn1.unsecure as asn1    
    try:
        # Uitpakken
        decoded, _ = decodeASN1(payload, asn1Spec=asn1.Ieee1609Dot2Data())
        
        # Protocol Version Validatie
        protocol_version = decoded['protocolVersion']
        protocol_version = int(protocol_version)
        if protocol_version < latest_protocol_version:
            terminal.text(f"Message protocol version ({protocol_version}) is outdated. Latest version is {latest_protocol_version}", color="red")

        # Presentatie
        payload = decoded['content']['unsecureData']

        values = []
        values.append(("payload", payload))

        return values, None
    
    except:
        terminal.text("Content type did not match the ASN.1 structure! UNSECURE", color="red")
    return None

"""de functie 'get_decoded_signed' doet hetzelfde als decode_signed, alleen geeft hij de waarde terug als bytes"""
def get_decoded_signed(payload: bytes):
    import CrashGuardIEEE.asn1.signed as asn1
    try:
        decoded, _ = decodeASN1(payload, asn1Spec=asn1.Ieee1609Dot2Data())
        
        # Protocol Version Validatie
        protocol_version = decoded['protocolVersion']
        protocol_version = int(protocol_version)
        if protocol_version < latest_protocol_version:
            terminal.text(f"Message protocol version ({protocol_version}) is outdated. Latest version is {latest_protocol_version}", color="red")
        
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

        values = []
        values.append(("payload", payload))
        values.append(("psid", psid))
        values.append(("generation time", generation))
        values.append(("signer name", signer))
        
        validation = []
        validation.append(("HeaderTime", v1[2]))
        validation.append(("CertificateTime", v2[2]))
        validation.append(("MessageSignature", v3[2]))
        validation.append(("CertificateSignature", v4[2]))

        terminal.logFase4(headerTime=v1, certTime=v2, sig=v3, certSig=v4)
        return values, validation
    
    except:
        terminal.text("Content type did not match the ASN.1 structure! SIGNED", color="red")
    return None

"""de functie 'get_decoded_encrypted' doet hetzelfde als decode_encrypted, alleen geeft hij de waarde terug als bytes"""
def get_decoded_encrypted(payload: bytes):
    import CrashGuardIEEE.asn1.encrypted as asn1
    try:
        # Uitpakken
        decoded, _ = decodeASN1(payload, asn1Spec=asn1.Ieee1609Dot2Data())
        
        # Protocol Version Validatie
        protocol_version = decoded['protocolVersion']
        protocol_version = int(protocol_version)
        if protocol_version < latest_protocol_version:
            terminal.text(f"Message protocol version ({protocol_version}) is outdated. Latest version is {latest_protocol_version}", color="red")
        
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

        values = []
        values.append(("pskId", received_pskId))
        values.append(("ciphertext", ciphertext))

        validation = []
        validation.append(("PskId", v1[2]))
        validation.append(("Encryptie", v2[2]))
        validation.append(("Payload", payload))

        # Presentatie
        terminal.logFase4(pskId=v1, enc=v2)
        return values, validation
    
    except Exception as e:
        terminal.text(f"Content type did not match the ASN.1 structure! ENCRYPTED\n{e}", color="red")
    return None

"""de functie 'get_decoded_enveloped' doet hetzelfde als decode_enveloped, alleen geeft hij de waarde terug als bytes"""
def get_decoded_enveloped(payload: bytes):
    import CrashGuardIEEE.asn1.enveloped as asn1
    try:
        # Uitpakken
        decoded, _ = decodeASN1(payload, asn1Spec=asn1.Ieee1609Dot2Data())
        
        # Protocol Version Validatie
        protocol_version = decoded['protocolVersion']
        protocol_version = int(protocol_version)
        if protocol_version < latest_protocol_version:
            terminal.text(f"Message protocol version ({protocol_version}) is outdated. Latest version is {latest_protocol_version}", color="red")

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
        
        values = []
        values.append(("pskId", received_pskId))
        values.append(("ciphertext", ciphertext))
        values.append(("payload", payload))
        values.append(("psid", psid))
        values.append(("generation time", generation))
        values.append(("signer name", signer))

        validation = []
        validation.append(("PskId", v1[2]))
        validation.append(("Encryptie", v2[2]))
        validation.append(("Payload", payload))
        validation.append(("HeaderTime", v3[2]))
        validation.append(("CertificateTime", v4[2]))
        validation.append(("MessageSignature", v5[2]))
        validation.append(("CertificateSignature", v6[2]))

        # Presentatie
        terminal.logFase4(headerTime=v3, certTime=v4, sig=v5, certSig=v6, pskId=v1, enc=v2)
        return values, validation
    
    except Exception as e:
        terminal.text(f"Content type did not match the ASN.1 structure! ENCRYPTED\n{e}", color="red")
    return None
"""Dit script bevat alle code voor het inpakken/encoding van het IEEE bericht bij de ontvanger/pijlwagen"""

# Allereerst importeren we de nodige open source libraries en alle functies en waardes van CrashGuardIEEE
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, decode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from pyasn1.codec.der.encoder import encode as encodeASN1
from CrashGuardIEEE import terminal, ROOT_CA_PRIVATE_KEY, SENDER_PRIVATE_KEY, PSK
from CrashGuardIEEE.timer import *
import time
import os

"""De functie 'encode_unsecure' is verantwoordelijk voor het inpakken van een IEEE bericht met het content type unsecure.
unsecure data bevat alleen de payload en heeft geen beveiligingsfuncties."""
def encode_unsecure(payload: bytes, timer: Timer | None = None) -> bytes:
    # eerst importeren we de juist ASN.1 structuren die nodig zijn voor unsecure data
    import CrashGuardIEEE.asn1.unsecure as asn1
    if timer: timer.startTimer()

    # ASN.1 types Ieee1609Dot2Data en Ieee1609Dot2Content worden aangemaakt en ingevuld
    ieee_data = asn1.Ieee1609Dot2Data()
    ieee_data['protocolVersion'] = 3
    ieee_data['contentType'] = 0
    ieee_data['content'] = asn1.Ieee1609Dot2Content()
    ieee_data['content']['unsecureData'] = payload
    if timer: timer.setTimeStamp("ASN1 inpakken: Ieee1609Dot2Data")
    
    terminal.printASN1(ieee_data)
    # ASN.1 encoding om het bericht te serializeren
    final_bytes = encodeASN1(ieee_data)
    if timer: 
        timer.setTimeStamp("ASN1 encoding: Ieee1609Dot2Data")
        timer.stopTimer()
    # de functie geeft het eindresultaat terug
    return final_bytes

"""De functie 'encode_signed' is verantwoordelijk voor het inpakken van een IEEE bericht met het content type signed.
signed data bevat naast de payload een signature van het bericht (ondertekend door de Pijlwagen) en een signature van het certificaat van de pijlwagen,
ondertekend door de ROOT CA.
Informatie over de waardes die worden toegewezen aan de ASN.1 velden worden in de officiele IEEE 1609.2 documentatie toegelicht."""
def encode_signed(payload: bytes, timer: Timer | None = None) -> bytes:
    # eerst importeren we de juist ASN.1 structuren die nodig zijn voor signed data
    import CrashGuardIEEE.asn1.signed as asn1
    if timer: timer.startTimer()

    # waardes voor HeaderInfo worden gedefinieerd
    PSID = 0x20
    GENERATION_TIME = int(time.time() * 1_000_000)
    EXPIRY_TIME = GENERATION_TIME + 60_000_000 # 60 seconden
    if timer: timer.setTimeStamp("HeaderInfo metdata creeren")

    # ASN.1 types SignedData, SignedDataPayload en HeaderInfo worden aangemaakt en ingevuld
    tbs_data = asn1.ToBeSignedData()
    tbs_data['payload'] = asn1.SignedDataPayload()
    tbs_data['payload']['data'] = payload
    tbs_data['headerInfo'] = asn1.HeaderInfo()
    tbs_data['headerInfo']['psid'] = PSID
    tbs_data['headerInfo']['generationTime'] = GENERATION_TIME
    tbs_data['headerInfo']['expiryTime'] = EXPIRY_TIME
    if timer: timer.setTimeStamp("ASN1 inpakken: ToBeSignedData")

    # ASN.1 types VerificationKeyIndicatorm EccP256CurvePoint en UncompressedP256 worden aangemaakt en ingevuld
    verify_key = asn1.VerificationKeyIndicator()
    SENDER_PUBLIC_KEY = SENDER_PRIVATE_KEY.public_key() # Sender/Pijlwagen public key wordt berekend op basis van de private key 
    numbers = SENDER_PUBLIC_KEY.public_numbers() # numbers worden berekend op basis van de public key
    x_bytes = numbers.x.to_bytes(32, 'big') # slaat de bytes van de x positie van de key op als x_bytes
    y_bytes = numbers.y.to_bytes(32, 'big') # slaat de bytes van de y positie van de key op als y_bytes
    if timer: timer.setTimeStamp("VerifyKey als X, Y")
    verify_key['ecdsaNistP256'] = asn1.EccP256CurvePoint()
    verify_key['ecdsaNistP256']['uncompressed'] = asn1.UncompressedP256()
    verify_key['ecdsaNistP256']['uncompressed']['x'] = x_bytes
    verify_key['ecdsaNistP256']['uncompressed']['y'] = y_bytes
    if timer: timer.setTimeStamp("ASN1 inpakken: VerifyKeyIndicator")

    # ASN.1 types ToBeSignedCertificate, CertificateId, HashedId3, ValidityPeriod en Duration worden aangemaakt en ingevuld
    tbs_cert = asn1.ToBeSignedCertificate()
    tbs_cert['id'] = asn1.CertificateId()
    tbs_cert['id']['name'] = "pijlwagen1234" # PLACEHOLDER
    tbs_cert['cracaId'] = asn1.HashedId3(b'\x01\x02\x03') # PLACEHOLDER
    tbs_cert['crlSeries'] = 0 # PLACEHOLDER
    tbs_cert['validityPeriod'] = asn1.ValidityPeriod()
    tbs_cert['validityPeriod']['start'] = int(time.time())
    tbs_cert['validityPeriod']['duration'] = asn1.Duration()
    tbs_cert['validityPeriod']['duration']['hours'] = 24
    tbs_cert['verifyKeyIndicator'] = verify_key
    if timer: timer.setTimeStamp("ASN1 inpakken: ToBeSignedCertificate")

    # ASN.1 types SignerIdentifier, CertificateType en IssuerIdentifier worden aangemaakt en ingevuld
    signer = asn1.SignerIdentifier()
    signer['certificate'] = asn1.Certificate()
    signer['certificate']['version'] = 1
    signer['certificate']['type'] = asn1.CertificateType(0)
    signer['certificate']['issuer'] = asn1.IssuerIdentifier()
    signer['certificate']['issuer']['sha256AndDigest'] = os.urandom(8) # PLACEHOLDER
    signer['certificate']['toBeSignedCert'] = tbs_cert
    if timer: timer.setTimeStamp("ASN1 inpakken: SignerIdentifier")
    cert_tbs_der = encodeASN1(tbs_cert) # ASN.1 encoding voordat de signature wordt gemaakt
    if timer: timer.setTimeStamp("ASN1 encoding: cert_tbs_der")
    cert_signature = ROOT_CA_PRIVATE_KEY.sign(cert_tbs_der, ec.ECDSA(hashes.SHA256())) # signature wordt gemaakt van het certificaat door middel van de ROOT CA private key
    if timer: timer.setTimeStamp("Private Key Signing")
    signer['certificate']['signature'] = cert_signature

    # ASN.1 types Signature en EcdsaP256Signature worden aangemaakt en ingevuld
    signature = asn1.Signature()
    tbs_der = encodeASN1(tbs_data)
    if timer: timer.setTimeStamp("ASN1 encoding: ToBeSignedData")
    # bericht wordt omgezet naar hash met de sha256 hashfunctie voordat hij wordt ondertekend
    digest = hashes.Hash(hashes.SHA256())
    digest.update(tbs_der)
    hash_value = digest.finalize()
    signature_der = SENDER_PRIVATE_KEY.sign(hash_value, ec.ECDSA(Prehashed(hashes.SHA256()))) # signature wordt gemaakt van de hash door middel van de ROOT CA private key
    if timer: timer.setTimeStamp("Private key Signing")
    r, s = decode_dss_signature(signature_der) # signature wordt uitgepakt als R en S
    if timer: timer.setTimeStamp("Signature als R, S")
    signature['ecdsaNistP256Signature'] = asn1.EcdsaP256Signature()
    signature['ecdsaNistP256Signature']['r'] = r.to_bytes(32, 'big')
    signature['ecdsaNistP256Signature']['s'] = s.to_bytes(32, 'big')

    # ASN.1 types SignedData en HashAlgorithm worden aangemaakt
    signed_data = asn1.SignedData()
    signed_data['hashId'] = asn1.HashAlgorithm(0) # 0 = sha256
    signed_data['tbsData'] = tbs_data
    signed_data['signer'] = signer
    signed_data['signature'] = signature
    if timer: timer.setTimeStamp("ASN1 inpakken: SignedData")

    # ASN.1 types Ieee1609Dot2Data en Ieee1609Dot2Content worden aangemaakt en ingevuld
    ieee_data = asn1.Ieee1609Dot2Data()
    ieee_data['protocolVersion'] = 3
    ieee_data['contentType'] = 1
    ieee_data['content'] = asn1.Ieee1609Dot2Content()
    ieee_data['content']['signedData'] = signed_data
    if timer: timer.setTimeStamp("ASN1 inpakken: Ieee1609Dot2Data")
    
    terminal.printASN1(ieee_data)
    # ASN.1 encoding om het bericht te serializeren
    final_bytes = encodeASN1(ieee_data)
    if timer: 
        timer.setTimeStamp("ASN1 encoding: Ieee1609Dot2Data")
        timer.stopTimer()
    # de functie geeft het eindresultaat terug
    return final_bytes

"""De functie 'encode_encrypted' is verantwoordelijk voor het inpakken van een IEEE bericht met het content type encrypted.
encrypted data bevat de geencrypte payload, die geencrypt wordt met behulp van een pre-shared key (PSK).
Informatie over de waardes die worden toegewezen aan de ASN.1 velden worden in de officiele IEEE 1609.2 documentatie toegelicht."""
def encode_encrypted(payload: bytes, timer: Timer | None = None) -> bytes:
    # eerst importeren we de juist ASN.1 structuren die nodig zijn voor encrypted data
    import CrashGuardIEEE.asn1.encrypted as asn1
    if timer: timer.startTimer()

    # PskId wordt berekent op basis van de pre-shared key
    digest = hashes.Hash(hashes.SHA256())
    digest.update(PSK)
    pskId = digest.finalize()[:8]
    if timer: timer.setTimeStamp("PskId berekend")

    # ASN.1 type RecipientInfo wordt 2x aangemaakt en ingevuld en opgeslagen in het ASN.1 type SequenceOfRecipientInfo
    recipient1 = asn1.RecipientInfo()
    recipient1['pskRecipInfo'] = pskId
    recipient2 = asn1.RecipientInfo()
    recipient2['pskRecipInfo'] = pskId
    recipients_seq = asn1.SequenceOfRecipientInfo()
    recipients_seq.append(recipient1)
    recipients_seq.append(recipient2)
    if timer: timer.setTimeStamp(f"ASN1 inpakken: RecipientInfo x{len(recipients_seq)}")

    # ASN.1 types SymmetricCiphertext en One28BitCcmCiphertext worden aangemaakt en ingevuld
    symmCiphertext = asn1.SymmetricCiphertext()
    symmCiphertext['aes128ccm'] = asn1.One28BitCcmCiphertext()
    nonce = os.urandom(12) # Nonce wordt aangemaakt als random bytes met een size van 12
    if timer: timer.setTimeStamp("Nonce berekend")
    aesccm = AESCCM(PSK) # AESCCM sleutel wordt berekend op basis van de pre-shared key
    if timer: timer.setTimeStamp("AESCCM Key berekend")
    ciphertext = aesccm.encrypt(nonce=nonce, data=payload, associated_data=None) # payload wordt geencrypt door middel van de nonce en AESCCM key
    if timer: timer.setTimeStamp(("AESCCM encryptie"))
    symmCiphertext['aes128ccm']['nonce'] = nonce
    symmCiphertext['aes128ccm']['ccmCiphertext'] = ciphertext
    if timer: timer.setTimeStamp("ASN1 inpakken: SymmetricCiphertext")

    # ASN.1 type EncryptedData wordt aangemaakt en ingevuld
    enc_data = asn1.EncryptedData()
    enc_data['recipients'] = recipients_seq
    enc_data['ciphertext'] = symmCiphertext
    if timer: timer.setTimeStamp("ASN1 inpakken: EncryptedData")

    # ASN.1 types Ieee1609Dot2Data en Ieee1609Dot2Content worden aangemaakt en ingevuld
    ieee_data = asn1.Ieee1609Dot2Data()
    ieee_data['protocolVersion'] = 3
    ieee_data['contentType'] = 2
    ieee_data['content'] = asn1.Ieee1609Dot2Content()
    ieee_data['content']['encryptedData'] = enc_data
    if timer: timer.setTimeStamp("ASN1 inpakken: Ieee1609Dot2Data")

    terminal.printASN1(ieee_data)
    # ASN.1 encoding om het bericht te serializeren
    final_bytes = encodeASN1(ieee_data)
    if timer: 
        timer.setTimeStamp("ASN1 encoding: Ieee1609Dot2Data")
        timer.stopTimer()
    # de functie geeft het eindresultaat terug
    return final_bytes

"""De functie 'encode_enveloped' is verantwoordelijk voor het inpakken van een IEEE bericht met het content type enveloped.
enveloped data bevat naast de payload een signature van het bericht (ondertekend door de Pijlwagen) en een signature van het certificaat van de pijlwagen,
ondertekend door de ROOT CA. Deze structuur wordt net als bij encrypted data geencrypt door middel van de pre-shared key.
Informatie over de waardes die worden toegewezen aan de ASN.1 velden worden in de officiele IEEE 1609.2 documentatie toegelicht."""
def encode_enveloped(payload: bytes, timer: Timer | None = None) -> bytes:
    # eerst importeren we de juist ASN.1 structuren die nodig zijn voor enveloped data
    import CrashGuardIEEE.asn1.enveloped as asn1
    if timer: timer.startTimer()

    # waardes voor HeaderInfo worden gedefinieerd
    PSID = 0x20
    GENERATION_TIME = int(time.time() * 1_000_000)
    EXPIRY_TIME = GENERATION_TIME + 60_000_000 # 60 seconden
    if timer: timer.setTimeStamp("HeaderInfo metdata creeren")

    # ASN.1 types SignedData, SignedDataPayload en HeaderInfo worden aangemaakt en ingevuld
    tbs_data = asn1.ToBeSignedData()
    tbs_data['payload'] = asn1.SignedDataPayload()
    tbs_data['payload']['data'] = payload
    tbs_data['headerInfo'] = asn1.HeaderInfo()
    tbs_data['headerInfo']['psid'] = PSID
    tbs_data['headerInfo']['generationTime'] = GENERATION_TIME
    tbs_data['headerInfo']['expiryTime'] = EXPIRY_TIME
    if timer: timer.setTimeStamp("ASN1 inpakken: ToBeSignedData")

    # ASN.1 types VerificationKeyIndicatorm EccP256CurvePoint en UncompressedP256 worden aangemaakt en ingevuld
    verify_key = asn1.VerificationKeyIndicator()
    SENDER_PUBLIC_KEY = SENDER_PRIVATE_KEY.public_key() # Sender/Pijlwagen public key wordt berekend op basis van de private key
    numbers = SENDER_PUBLIC_KEY.public_numbers() # numbers worden berekend op basis van de public key
    x_bytes = numbers.x.to_bytes(32, 'big') # slaat de bytes van de x positie van de key op als x_bytes
    y_bytes = numbers.y.to_bytes(32, 'big') # slaat de bytes van de y positie van de key op als y_bytes
    if timer: timer.setTimeStamp("VerifyKey als X, Y")
    verify_key['ecdsaNistP256'] = asn1.EccP256CurvePoint()
    verify_key['ecdsaNistP256']['uncompressed'] = asn1.UncompressedP256()
    verify_key['ecdsaNistP256']['uncompressed']['x'] = x_bytes
    verify_key['ecdsaNistP256']['uncompressed']['y'] = y_bytes
    if timer: timer.setTimeStamp("ASN1 inpakken: VerifyKeyIndicator")

    # ASN.1 types ToBeSignedCertificate, CertificateId, HashedId3, ValidityPeriod en Duration worden aangemaakt en ingevuld
    tbs_cert = asn1.ToBeSignedCertificate()
    tbs_cert['id'] = asn1.CertificateId()
    tbs_cert['id']['name'] = "pijlwagen1234" # PLACEHOLDER
    tbs_cert['cracaId'] = asn1.HashedId3(b'\x01\x02\x03') # PLACEHOLDER
    tbs_cert['crlSeries'] = 0 # PLACEHOLDER
    tbs_cert['validityPeriod'] = asn1.ValidityPeriod()
    tbs_cert['validityPeriod']['start'] = int(time.time())
    tbs_cert['validityPeriod']['duration'] = asn1.Duration()
    tbs_cert['validityPeriod']['duration']['hours'] = 24
    tbs_cert['verifyKeyIndicator'] = verify_key
    if timer: timer.setTimeStamp("ASN1 inpakken: ToBeSignedCertificate")

    # ASN.1 types SignerIdentifier, CertificateType en IssuerIdentifier worden aangemaakt en ingevuld
    signer = asn1.SignerIdentifier()
    signer['certificate'] = asn1.Certificate()
    signer['certificate']['version'] = 1
    signer['certificate']['type'] = asn1.CertificateType(0)
    signer['certificate']['issuer'] = asn1.IssuerIdentifier()
    signer['certificate']['issuer']['sha256AndDigest'] = os.urandom(8) # PLACEHOLDER
    signer['certificate']['toBeSignedCert'] = tbs_cert
    if timer: timer.setTimeStamp("ASN1 inpakken: SignerIdentifier")
    cert_tbs_der = encodeASN1(tbs_cert) # ASN.1 encoding voordat de signature wordt gemaakt
    if timer: timer.setTimeStamp("ASN1 encoding: cert_tbs_der")
    cert_signature = ROOT_CA_PRIVATE_KEY.sign(cert_tbs_der, ec.ECDSA(hashes.SHA256())) # signature wordt gemaakt van het certificaat door middel van de ROOT CA private key
    if timer: timer.setTimeStamp("Private Key Signing")
    signer['certificate']['signature'] = cert_signature
    if timer: timer.setTimeStamp("Signer Signature inpakken")

    # ASN.1 types Signature en EcdsaP256Signature worden aangemaakt en ingevuld
    signature = asn1.Signature()
    tbs_der = encodeASN1(tbs_data)
    if timer: timer.setTimeStamp("ASN1 encoding: ToBeSignedData")
    # bericht wordt omgezet naar hash met de sha256 hashfunctie voordat hij wordt ondertekend
    digest = hashes.Hash(hashes.SHA256())
    digest.update(tbs_der)
    hash_value = digest.finalize()
    signature_der = SENDER_PRIVATE_KEY.sign(hash_value, ec.ECDSA(Prehashed(hashes.SHA256()))) # signature wordt gemaakt van de hash door middel van de ROOT CA private key
    if timer: timer.setTimeStamp("Private key Signing")
    r, s = decode_dss_signature(signature_der) # signature wordt uitgepakt als R en S
    if timer: timer.setTimeStamp("Signature als R, S")
    signature['ecdsaNistP256Signature'] = asn1.EcdsaP256Signature()
    signature['ecdsaNistP256Signature']['r'] = r.to_bytes(32, 'big')
    signature['ecdsaNistP256Signature']['s'] = s.to_bytes(32, 'big')

    # ASN.1 types SignedData en HashAlgorithm worden aangemaakt
    signed_data = asn1.SignedData()
    signed_data['hashId'] = asn1.HashAlgorithm(0)
    signed_data['tbsData'] = tbs_data
    signed_data['signer'] = signer
    signed_data['signature'] = signature
    if timer: timer.setTimeStamp("ASN1 inpakken: SignedData")

    signed_der = encodeASN1(signed_data) # ASN.1 encoding voordat SignedData geencrypt wordt
    if timer: timer.setTimeStamp("ASN1 encoding: SignedData")
    # PskId wordt berekent op basis van de pre-shared key
    digest = hashes.Hash(hashes.SHA256())
    digest.update(PSK)
    pskId = digest.finalize()[:8]
    if timer: timer.setTimeStamp("PskId berekend")
    nonce = os.urandom(12)
    if timer: timer.setTimeStamp("Nonce berekend")
    aesccm = AESCCM(PSK) # AESCCM sleutel wordt berekend op basis van de pre-shared key
    if timer: timer.setTimeStamp("AESCCM Key berekend")
    ciphertext = aesccm.encrypt(nonce, signed_der, associated_data=None) # payload wordt geencrypt door middel van de nonce en AESCCM key
    if timer: timer.setTimeStamp("AESCCM encryptie")

    # ASN.1 types SymmetricCiphertext en One28BitCcmCiphertext worden aangemaakt en ingevuld
    symmCiphertext = asn1.SymmetricCiphertext()
    symmCiphertext['aes128ccm'] = asn1.One28BitCcmCiphertext()
    symmCiphertext['aes128ccm']['nonce'] = nonce
    symmCiphertext['aes128ccm']['ccmCiphertext'] = ciphertext
    if timer: timer.setTimeStamp("ASN1 inpakken: SymmetricCiphertext")

    # ASN.1 type RecipientInfo wordt 2x aangemaakt en ingevuld en opgeslagen in het ASN.1 type SequenceOfRecipientInfo
    recipient1 = asn1.RecipientInfo()
    recipient1['pskRecipInfo'] = asn1.PreSharedKeyRecipientInfo(pskId)
    recipient2 = asn1.RecipientInfo()
    recipient2['pskRecipInfo'] = asn1.PreSharedKeyRecipientInfo(pskId)
    recipients_seq = asn1.SequenceOfRecipientInfo()
    recipients_seq.append(recipient1)
    recipients_seq.append(recipient2)
    if timer: timer.setTimeStamp(f"ASN1 inpakken: RecipientInfo x{len(recipients_seq)}")

    # ASN.1 type EncryptedData wordt aangemaakt en ingevuld
    enc_data = asn1.EncryptedData()
    enc_data['recipients'] = recipients_seq
    enc_data['ciphertext'] = symmCiphertext
    if timer: timer.setTimeStamp("ASN1 inpakken: EncryptedData")

    # ASN.1 types Ieee1609Dot2Data en Ieee1609Dot2Content worden aangemaakt en ingevuld
    ieee_data = asn1.Ieee1609Dot2Data()
    ieee_data['protocolVersion'] = 3
    ieee_data['contentType'] = 3
    ieee_data['content'] = asn1.Ieee1609Dot2Content()
    ieee_data['content']['encryptedData'] = enc_data
    if timer: timer.setTimeStamp("ASN1 inpakken: Ieee1609Dot2Data")

    terminal.printASN1(ieee_data)
    # ASN.1 encoding om het bericht te serializeren
    final_bytes = encodeASN1(ieee_data)
    if timer: 
        timer.setTimeStamp("ASN1 encoding: Ieee1609Dot2Data")
        timer.stopTimer()
    # de functie geeft het eindresultaat terug
    return final_bytes
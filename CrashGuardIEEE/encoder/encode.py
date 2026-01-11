from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, decode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from pyasn1.codec.der.encoder import encode as encodeASN1
from CrashGuardIEEE import terminal, PRIVATE_KEY, PSK
from CrashGuardIEEE.timer import *
import time
import os

def encode_unsecure(payload: bytes, timer: Timer | None = None) -> bytes:
    """
    Eenvoudige message met raw payload; alleen gebruiken voor tests.
    """
    import CrashGuardIEEE.asn1.unsecure as asn1
    if timer: timer.startTimer()

    ieee_data = asn1.Ieee1609Dot2Data()
    ieee_data['protocolVersion'] = 3
    ieee_data['contentType'] = 0
    ieee_data['content'] = asn1.Ieee1609Dot2Content()
    ieee_data['content']['unsecureData'] = payload
    if timer: timer.setTimeStamp("ASN1 inpakken: Ieee1609Dot2Data")
    
    terminal.printASN1(ieee_data)
    final_bytes = encodeASN1(ieee_data)
    if timer: 
        timer.setTimeStamp("ASN1 encoding: Ieee1609Dot2Data")
        timer.stopTimer()
    return final_bytes

def encode_signed(payload: bytes, timer: Timer | None = None) -> bytes:
    """
    Maak een signed message met signature en certificate. De ontvanger kan het bericht authentiseren door controle van de signature en het certificaat.
    """
    import CrashGuardIEEE.asn1.signed as asn1
    if timer: timer.startTimer()

    PSID = 0x20
    GENERATION_TIME = int(time.time() * 1_000_000)
    EXPIRY_TIME = GENERATION_TIME + 10_000_000
    if timer: timer.setTimeStamp("HeaderInfo metdata creeren")

    tbs_data = asn1.ToBeSignedData()
    tbs_data['payload'] = asn1.SignedDataPayload()
    tbs_data['payload']['data'] = payload
    tbs_data['headerInfo'] = asn1.HeaderInfo()
    tbs_data['headerInfo']['psid'] = PSID
    tbs_data['headerInfo']['generationTime'] = GENERATION_TIME
    tbs_data['headerInfo']['expiryTime'] = EXPIRY_TIME
    if timer: timer.setTimeStamp("ASN1 inpakken: ToBeSignedData")

    verify_key = asn1.VerificationKeyIndicator()
    PUBLIC_KEY = PRIVATE_KEY.public_key()
    numbers = PUBLIC_KEY.public_numbers()
    x_bytes = numbers.x.to_bytes(32, 'big')
    y_bytes = numbers.y.to_bytes(32, 'big')
    if timer: timer.setTimeStamp("VerifyKey als X, Y")
    verify_key['ecdsaNistP256'] = asn1.EccP256CurvePoint()
    verify_key['ecdsaNistP256']['uncompressed'] = asn1.UncompressedP256()
    verify_key['ecdsaNistP256']['uncompressed']['x'] = x_bytes
    verify_key['ecdsaNistP256']['uncompressed']['y'] = y_bytes
    if timer: timer.setTimeStamp("ASN1 inpakken: VerifyKeyIndicator")

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

    signer = asn1.SignerIdentifier()
    signer['certificate'] = asn1.Certificate()
    signer['certificate']['version'] = 1
    signer['certificate']['type'] = asn1.CertificateType(0)
    signer['certificate']['issuer'] = asn1.IssuerIdentifier()
    signer['certificate']['issuer']['sha256AndDigest'] = os.urandom(8) # PLACEHOLDER
    signer['certificate']['toBeSignedCert'] = tbs_cert
    if timer: timer.setTimeStamp("ASN1 inpakken: SignerIdentifier")
    cert_tbs_der = encodeASN1(tbs_cert)
    if timer: timer.setTimeStamp("ASN1 encoding: cert_tbs_der")
    cert_signature = PRIVATE_KEY.sign(cert_tbs_der, ec.ECDSA(hashes.SHA256()))
    if timer: timer.setTimeStamp("Private Key Signing")
    signer['certificate']['signature'] = cert_signature

    signature = asn1.Signature()
    tbs_der = encodeASN1(tbs_data)
    if timer: timer.setTimeStamp("ASN1 encoding: ToBeSignedData")
    digest = hashes.Hash(hashes.SHA256())
    digest.update(tbs_der)
    hash_value = digest.finalize()
    signature_der = PRIVATE_KEY.sign(hash_value, ec.ECDSA(Prehashed(hashes.SHA256())))
    if timer: timer.setTimeStamp("Private key Signing")
    r, s = decode_dss_signature(signature_der)
    if timer: timer.setTimeStamp("Signature als R, S")
    signature['ecdsaNistP256Signature'] = asn1.EcdsaP256Signature()
    signature['ecdsaNistP256Signature']['r'] = r.to_bytes(32, 'big')
    signature['ecdsaNistP256Signature']['s'] = s.to_bytes(32, 'big')

    signed_data = asn1.SignedData()
    signed_data['hashId'] = asn1.HashAlgorithm(0)
    signed_data['tbsData'] = tbs_data
    signed_data['signer'] = signer
    signed_data['signature'] = signature
    if timer: timer.setTimeStamp("ASN1 inpakken: SignedData")

    ieee_data = asn1.Ieee1609Dot2Data()
    ieee_data['protocolVersion'] = 3
    ieee_data['contentType'] = 1
    ieee_data['content'] = asn1.Ieee1609Dot2Content()
    ieee_data['content']['signedData'] = signed_data
    if timer: timer.setTimeStamp("ASN1 inpakken: Ieee1609Dot2Data")
    
    terminal.printASN1(ieee_data)
    final_bytes = encodeASN1(ieee_data)
    if timer: 
        timer.setTimeStamp("ASN1 encoding: Ieee1609Dot2Data")
        timer.stopTimer()
    return final_bytes

def encode_encrypted(payload: bytes, timer: Timer | None = None) -> bytes:
    """
    Versleuteld/encrypted bericht wat versleuteld wordt met AESCCM sleutel. Waarborgt de vetrouwelijkeheid van het bericht.
    """
    import CrashGuardIEEE.asn1.encrypted as asn1
    if timer: timer.startTimer()

    digest = hashes.Hash(hashes.SHA256())
    digest.update(PSK)
    pskId = digest.finalize()[:8]
    if timer: timer.setTimeStamp("PskId berekend")

    recipient1 = asn1.RecipientInfo()
    recipient1['pskRecipInfo'] = pskId
    recipient2 = asn1.RecipientInfo()
    recipient2['pskRecipInfo'] = pskId
    recipients_seq = asn1.SequenceOfRecipientInfo()
    recipients_seq.append(recipient1)
    recipients_seq.append(recipient2)
    if timer: timer.setTimeStamp(f"ASN1 inpakken: RecipientInfo x{len(recipients_seq)}")

    symmCiphertext = asn1.SymmetricCiphertext()
    symmCiphertext['aes128ccm'] = asn1.One28BitCcmCiphertext()
    nonce = os.urandom(12)
    if timer: timer.setTimeStamp("Nonce berekend")
    aesccm = AESCCM(PSK)
    if timer: timer.setTimeStamp("AESCCM Key berekend")
    ciphertext = aesccm.encrypt(nonce=nonce, data=payload, associated_data=None)
    if timer: timer.setTimeStamp(("AESCCM encryptie"))
    symmCiphertext['aes128ccm']['nonce'] = nonce
    symmCiphertext['aes128ccm']['ccmCiphertext'] = ciphertext
    if timer: timer.setTimeStamp("ASN1 inpakken: SymmetricCiphertext")

    enc_data = asn1.EncryptedData()
    enc_data['recipients'] = recipients_seq
    enc_data['ciphertext'] = symmCiphertext
    if timer: timer.setTimeStamp("ASN1 inpakken: EncryptedData")

    ieee_data = asn1.Ieee1609Dot2Data()
    ieee_data['protocolVersion'] = 3
    ieee_data['contentType'] = 2
    ieee_data['content'] = asn1.Ieee1609Dot2Content()
    ieee_data['content']['encryptedData'] = enc_data
    if timer: timer.setTimeStamp("ASN1 inpakken: Ieee1609Dot2Data")

    terminal.printASN1(ieee_data)
    final_bytes = encodeASN1(ieee_data)
    if timer: 
        timer.setTimeStamp("ASN1 encoding: Ieee1609Dot2Data")
        timer.stopTimer()
    return final_bytes

def encode_enveloped(payload: bytes, timer: Timer | None = None) -> bytes:
    """
    Combinatie van signed & encrypted, waarbij SignedData wordt geencrypt. Waarborgt integriteit en vertrouwelijkheid.
    """
    import CrashGuardIEEE.asn1.enveloped as asn1
    if timer: timer.startTimer()

    PSID = 0x20
    GENERATION_TIME = int(time.time() * 1_000_000)
    EXPIRY_TIME = GENERATION_TIME + 10_000_000
    if timer: timer.setTimeStamp("HeaderInfo metdata creeren")

    tbs_data = asn1.ToBeSignedData()
    tbs_data['payload'] = asn1.SignedDataPayload()
    tbs_data['payload']['data'] = payload
    tbs_data['headerInfo'] = asn1.HeaderInfo()
    tbs_data['headerInfo']['psid'] = PSID
    tbs_data['headerInfo']['generationTime'] = GENERATION_TIME
    tbs_data['headerInfo']['expiryTime'] = EXPIRY_TIME
    if timer: timer.setTimeStamp("ASN1 inpakken: ToBeSignedData")

    verify_key = asn1.VerificationKeyIndicator()
    PUBLIC_KEY = PRIVATE_KEY.public_key()
    numbers = PUBLIC_KEY.public_numbers()
    x_bytes = numbers.x.to_bytes(32, 'big')
    y_bytes = numbers.y.to_bytes(32, 'big')
    if timer: timer.setTimeStamp("VerifyKey als X, Y")
    verify_key['ecdsaNistP256'] = asn1.EccP256CurvePoint()
    verify_key['ecdsaNistP256']['uncompressed'] = asn1.UncompressedP256()
    verify_key['ecdsaNistP256']['uncompressed']['x'] = x_bytes
    verify_key['ecdsaNistP256']['uncompressed']['y'] = y_bytes
    if timer: timer.setTimeStamp("ASN1 inpakken: VerifyKeyIndicator")

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

    signer = asn1.SignerIdentifier()
    signer['certificate'] = asn1.Certificate()
    signer['certificate']['version'] = 1
    signer['certificate']['type'] = asn1.CertificateType(0)
    signer['certificate']['issuer'] = asn1.IssuerIdentifier()
    signer['certificate']['issuer']['sha256AndDigest'] = os.urandom(8) # PLACEHOLDER
    signer['certificate']['toBeSignedCert'] = tbs_cert
    if timer: timer.setTimeStamp("ASN1 inpakken: SignerIdentifier")
    cert_tbs_der = encodeASN1(tbs_cert)
    if timer: timer.setTimeStamp("ASN1 encoding: cert_tbs_der")
    cert_signature = PRIVATE_KEY.sign(cert_tbs_der, ec.ECDSA(hashes.SHA256()))
    if timer: timer.setTimeStamp("Private Key Signing")
    signer['certificate']['signature'] = cert_signature
    if timer: timer.setTimeStamp("Signer Signature inpakken")

    signature = asn1.Signature()
    tbs_der = encodeASN1(tbs_data)
    if timer: timer.setTimeStamp("ASN1 encoding: ToBeSignedData")
    digest = hashes.Hash(hashes.SHA256())
    digest.update(tbs_der)
    hash_value = digest.finalize()
    signature_der = PRIVATE_KEY.sign(hash_value, ec.ECDSA(Prehashed(hashes.SHA256())))
    if timer: timer.setTimeStamp("Private key Signing")
    r, s = decode_dss_signature(signature_der)
    if timer: timer.setTimeStamp("Signature als R, S")
    signature['ecdsaNistP256Signature'] = asn1.EcdsaP256Signature()
    signature['ecdsaNistP256Signature']['r'] = r.to_bytes(32, 'big')
    signature['ecdsaNistP256Signature']['s'] = s.to_bytes(32, 'big')

    signed_data = asn1.SignedData()
    signed_data['hashId'] = asn1.HashAlgorithm(0)
    signed_data['tbsData'] = tbs_data
    signed_data['signer'] = signer
    signed_data['signature'] = signature
    if timer: timer.setTimeStamp("ASN1 inpakken: SignedData")

    signed_der = encodeASN1(signed_data)
    if timer: timer.setTimeStamp("ASN1 encoding: SignedData")
    digest = hashes.Hash(hashes.SHA256())
    digest.update(PSK)
    pskId = digest.finalize()[:8]
    if timer: timer.setTimeStamp("PskId berekend")
    nonce = os.urandom(12)
    if timer: timer.setTimeStamp("Nonce berekend")
    aesccm = AESCCM(PSK)
    if timer: timer.setTimeStamp("AESCCM Key berekend")
    ciphertext = aesccm.encrypt(nonce, signed_der, associated_data=None)
    if timer: timer.setTimeStamp("AESCCM encryptie")

    symmCiphertext = asn1.SymmetricCiphertext()
    symmCiphertext['aes128ccm'] = asn1.One28BitCcmCiphertext()
    symmCiphertext['aes128ccm']['nonce'] = nonce
    symmCiphertext['aes128ccm']['ccmCiphertext'] = ciphertext
    if timer: timer.setTimeStamp("ASN1 inpakken: SymmetricCiphertext")

    recipient1 = asn1.RecipientInfo()
    recipient1['pskRecipInfo'] = asn1.PreSharedKeyRecipientInfo(pskId)
    recipient2 = asn1.RecipientInfo()
    recipient2['pskRecipInfo'] = asn1.PreSharedKeyRecipientInfo(pskId)
    recipients_seq = asn1.SequenceOfRecipientInfo()
    recipients_seq.append(recipient1)
    recipients_seq.append(recipient2)
    if timer: timer.setTimeStamp(f"ASN1 inpakken: RecipientInfo x{len(recipients_seq)}")

    enc_data = asn1.EncryptedData()
    enc_data['recipients'] = recipients_seq
    enc_data['ciphertext'] = symmCiphertext
    if timer: timer.setTimeStamp("ASN1 inpakken: EncryptedData")

    ieee_data = asn1.Ieee1609Dot2Data()
    ieee_data['protocolVersion'] = 3
    ieee_data['contentType'] = 3
    ieee_data['content'] = asn1.Ieee1609Dot2Content()
    ieee_data['content']['encryptedData'] = enc_data
    if timer: timer.setTimeStamp("ASN1 inpakken: Ieee1609Dot2Data")

    terminal.printASN1(ieee_data)
    final_bytes = encodeASN1(ieee_data)
    if timer: 
        timer.setTimeStamp("ASN1 encoding: Ieee1609Dot2Data")
        timer.stopTimer()
    return final_bytes
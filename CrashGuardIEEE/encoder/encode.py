from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, decode_dss_signature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.asymmetric import ec
from CrashGuardIEEE import asn1, terminal, PRIVATE_KEY, PSK
from pyasn1.codec.der.encoder import encode as encodeASN1
import time
import os

def encode_unsecure(payload: bytes) -> bytes:
    """
    Eenvoudige message met raw payload; alleen gebruiken voor tests.
    """
    ieee_data = asn1.Ieee1609Dot2Data()
    ieee_data['protocolVersion'] = 3
    ieee_data['content'] = asn1.Ieee1609Dot2Content()
    ieee_data['content']['unsecureData'] = payload
    
    terminal.printASN1(ieee_data)
    final_bytes = encodeASN1(ieee_data)
    return final_bytes

def encode_signed(payload: bytes) -> bytes:
    """
    Maak een signed message met signature en certificate. De ontvanger kan het bericht authentiseren door controle van de signature en het certificaat.
    """
    PSID = 0x20
    GENERATION_TIME = int(time.time() * 1_000_000)
    EXPIRY_TIME = GENERATION_TIME + 10_000_000

    tbs_data = asn1.ToBeSignedData()
    tbs_data['payload'] = asn1.SignedDataPayload()
    tbs_data['payload']['data'] = payload
    tbs_data['headerInfo'] = asn1.HeaderInfo()
    tbs_data['headerInfo']['psid'] = PSID
    tbs_data['headerInfo']['generationTime'] = GENERATION_TIME
    tbs_data['headerInfo']['expiryTime'] = EXPIRY_TIME

    verify_key = asn1.VerificationKeyIndicator()
    PUBLIC_KEY = PRIVATE_KEY.public_key()
    numbers = PUBLIC_KEY.public_numbers()
    x_bytes = numbers.x.to_bytes(32, 'big')
    y_bytes = numbers.y.to_bytes(32, 'big')
    verify_key['ecdsaNistP256'] = asn1.EccP256CurvePoint()
    verify_key['ecdsaNistP256']['uncompressed'] = asn1.UncompressedP256()
    verify_key['ecdsaNistP256']['uncompressed']['x'] = x_bytes
    verify_key['ecdsaNistP256']['uncompressed']['y'] = y_bytes

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

    signer = asn1.SignerIdentifier()
    signer['certificate'] = asn1.Certificate()
    signer['certificate']['version'] = 1
    signer['certificate']['type'] = asn1.CertificateType(0)
    signer['certificate']['issuer'] = asn1.IssuerIdentifier()
    signer['certificate']['issuer']['sha256AndDigest'] = os.urandom(8) # PLACEHOLDER
    signer['certificate']['toBeSignedCert'] = tbs_cert
    cert_tbs_der = encodeASN1(tbs_cert)
    cert_signature = PRIVATE_KEY.sign(cert_tbs_der, ec.ECDSA(hashes.SHA256()))
    signer['certificate']['signature'] = cert_signature

    signature = asn1.Signature()
    tbs_der = encodeASN1(tbs_data)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(tbs_der)
    hash_value = digest.finalize()
    signature_der = PRIVATE_KEY.sign(hash_value, ec.ECDSA(Prehashed(hashes.SHA256())))
    r, s = decode_dss_signature(signature_der)
    signature['ecdsaNistP256Signature'] = asn1.EcdsaP256Signature()
    signature['ecdsaNistP256Signature']['r'] = r.to_bytes(32, 'big')
    signature['ecdsaNistP256Signature']['s'] = s.to_bytes(32, 'big')

    signed_data = asn1.SignedData()
    signed_data['hashId'] = asn1.HashAlgorithm(0)
    signed_data['tbsData'] = tbs_data
    signed_data['signer'] = signer
    signed_data['signature'] = signature

    ieee_data = asn1.Ieee1609Dot2Data()
    ieee_data['protocolVersion'] = 3
    ieee_data['content'] = asn1.Ieee1609Dot2Content()
    ieee_data['content']['signedData'] = signed_data
    
    terminal.printASN1(ieee_data)
    final_bytes = encodeASN1(ieee_data)
    return final_bytes

def encode_encrypted(payload: bytes) -> bytes:
    """
    Versleuteld/encrypted bericht wat versleuteld wordt met AESCCM sleutel. Waarborgt de vetrouwelijkeheid van het bericht.
    """
    digest = hashes.Hash(hashes.SHA256())
    digest.update(PSK)
    pskId = digest.finalize()[:8]

    recipient1 = asn1.RecipientInfo()
    recipient1['pskRecipInfo'] = asn1.PreSharedKeyRecipientInfo(pskId)
    recipient2 = asn1.RecipientInfo()
    recipient2['pskRecipInfo'] = asn1.PreSharedKeyRecipientInfo(pskId)
    recipients_seq = asn1.SequenceOfRecipientInfo()
    recipients_seq.append(recipient1)
    recipients_seq.append(recipient2)

    symmCiphertext = asn1.SymmetricCiphertext()
    symmCiphertext['aes128ccm'] = asn1.One28BitCcmCiphertext()
    nonce = os.urandom(12)
    aesccm = AESCCM(PSK)
    ciphertext = aesccm.encrypt(nonce=nonce, data=payload, associated_data=None)
    symmCiphertext['aes128ccm']['nonce'] = nonce
    symmCiphertext['aes128ccm']['ccmCiphertext'] = ciphertext

    enc_data = asn1.EncryptedData()
    enc_data['recipients'] = recipients_seq
    enc_data['ciphertext'] = symmCiphertext

    ieee_data = asn1.Ieee1609Dot2Data()
    ieee_data['protocolVersion'] = 3
    ieee_data['content'] = asn1.Ieee1609Dot2Content()
    ieee_data['content']['encryptedData'] = enc_data

    terminal.printASN1(ieee_data)
    final_bytes = encodeASN1(ieee_data)
    return final_bytes

def encode_enveloped(payload: bytes) -> bytes:
    """
    Combinatie van signed & encrypted, waarbij SignedData wordt geencrypt. Waarborgt integriteit en vertrouwelijkheid.
    """
    PSID = 0x20
    GENERATION_TIME = int(time.time() * 1_000_000)
    EXPIRY_TIME = GENERATION_TIME + 10_000_000

    tbs_data = asn1.ToBeSignedData()
    tbs_data['payload'] = asn1.SignedDataPayload()
    tbs_data['payload']['data'] = payload
    tbs_data['headerInfo'] = asn1.HeaderInfo()
    tbs_data['headerInfo']['psid'] = PSID
    tbs_data['headerInfo']['generationTime'] = GENERATION_TIME
    tbs_data['headerInfo']['expiryTime'] = EXPIRY_TIME

    verify_key = asn1.VerificationKeyIndicator()
    PUBLIC_KEY = PRIVATE_KEY.public_key()
    numbers = PUBLIC_KEY.public_numbers()
    x_bytes = numbers.x.to_bytes(32, 'big')
    y_bytes = numbers.y.to_bytes(32, 'big')
    verify_key['ecdsaNistP256'] = asn1.EccP256CurvePoint()
    verify_key['ecdsaNistP256']['uncompressed'] = asn1.UncompressedP256()
    verify_key['ecdsaNistP256']['uncompressed']['x'] = x_bytes
    verify_key['ecdsaNistP256']['uncompressed']['y'] = y_bytes

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

    signer = asn1.SignerIdentifier()
    signer['certificate'] = asn1.Certificate()
    signer['certificate']['version'] = 1
    signer['certificate']['type'] = asn1.CertificateType(0)
    signer['certificate']['issuer'] = asn1.IssuerIdentifier()
    signer['certificate']['issuer']['sha256AndDigest'] = os.urandom(8) # PLACEHOLDER
    signer['certificate']['toBeSignedCert'] = tbs_cert
    cert_tbs_der = encodeASN1(tbs_cert)
    cert_signature = PRIVATE_KEY.sign(cert_tbs_der, ec.ECDSA(hashes.SHA256()))
    signer['certificate']['signature'] = cert_signature

    signature = asn1.Signature()
    tbs_der = encodeASN1(tbs_data)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(tbs_der)
    hash_value = digest.finalize()
    signature_der = PRIVATE_KEY.sign(
        hash_value, ec.ECDSA(Prehashed(hashes.SHA256()))
    )
    r, s = decode_dss_signature(signature_der)
    signature['ecdsaNistP256Signature'] = asn1.EcdsaP256Signature()
    signature['ecdsaNistP256Signature']['r'] = r.to_bytes(32, 'big')
    signature['ecdsaNistP256Signature']['s'] = s.to_bytes(32, 'big')

    signed_data = asn1.SignedData()
    signed_data['hashId'] = asn1.HashAlgorithm(0)
    signed_data['tbsData'] = tbs_data
    signed_data['signer'] = signer
    signed_data['signature'] = signature

    signed_der = encodeASN1(signed_data)
    digest = hashes.Hash(hashes.SHA256())
    digest.update(PSK)
    pskId = digest.finalize()[:8]
    nonce = os.urandom(12)
    aesccm = AESCCM(PSK)
    ciphertext = aesccm.encrypt(nonce, signed_der, associated_data=None)

    symmCiphertext = asn1.SymmetricCiphertext()
    symmCiphertext['aes128ccm'] = asn1.One28BitCcmCiphertext()
    symmCiphertext['aes128ccm']['nonce'] = nonce
    symmCiphertext['aes128ccm']['ccmCiphertext'] = ciphertext

    recipient1 = asn1.RecipientInfo()
    recipient1['pskRecipInfo'] = asn1.PreSharedKeyRecipientInfo(pskId)
    recipient2 = asn1.RecipientInfo()
    recipient2['pskRecipInfo'] = asn1.PreSharedKeyRecipientInfo(pskId)
    recipients_seq = asn1.SequenceOfRecipientInfo()
    recipients_seq.append(recipient1)
    recipients_seq.append(recipient2)

    enc_data = asn1.EncryptedData()
    enc_data['recipients'] = recipients_seq
    enc_data['ciphertext'] = symmCiphertext

    ieee_data = asn1.Ieee1609Dot2Data()
    ieee_data['protocolVersion'] = 3
    ieee_data['content'] = asn1.Ieee1609Dot2Content()
    ieee_data['content']['encryptedData'] = enc_data

    terminal.printASN1(ieee_data)
    final_bytes = encodeASN1(ieee_data)
    return final_bytes
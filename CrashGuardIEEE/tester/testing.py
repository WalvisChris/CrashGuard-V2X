from CrashGuardIEEE import MESSAGE, terminal, createPSK, createRootCAKeys, createSenderKeys, saveMessage, saveReplay, getReplay, encoder
from CrashGuardIEEE.timer import *
from main import _decode
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed, decode_dss_signature
from cryptography.hazmat.primitives.ciphers.aead import AESCCM
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
from pyasn1.codec.der.encoder import encode as encodeASN1 
from pyasn1.codec.der.decoder import decode as decodeASN1
from pyasn1.type import univ
import os

def MITM():
    terminal.clear()
    if MESSAGE == None:
        terminal.text(text="No message to manipulate!", color="red")
    else:
        top_level, _ = decodeASN1(MESSAGE, asn1Spec=univ.Sequence())
        content_type = int(top_level[1])

        match content_type:
            # UNSECURE
            case 0:
                import CrashGuardIEEE.asn1.unsecure as asn1
                decoded, _ = decodeASN1(MESSAGE, asn1Spec=asn1.Ieee1609Dot2Data())
                MANIPULATE = [
                    "< Done",
                    "protocolVersion",
                    "contentType",
                    "payload"
                ]
                manipulating = True
                
                while manipulating:
                    terminal.clear()
                    title = terminal.getASN1Text(obj=decoded)                 
                    choice = terminal.menu(MANIPULATE, title)

                    match choice:
                        # DONE
                        case 1:
                            msg = encodeASN1(decoded)
                            saveMessage(msg)
                            terminal.clear()
                            terminal.text(text="Done manipulating message:")
                            terminal.printASN1(decoded)
                            manipulating = False
                        # PROTOCOL VERSION
                        case 2:
                            protocol_version = int(terminal.input(prompt="protocol version: "))
                            decoded['protocolVersion'] = protocol_version
                        # CONTENT TYPE
                        case 3:
                            content_type = int(terminal.input(prompt="content type: "))
                            decoded['contentType'] = content_type
                        # PAYLOAD
                        case 4:
                            payload = terminal.input(prompt="payload: ")
                            payload_bytes = payload.encode('utf-8')
                            decoded['content']['unsecureData'] = payload_bytes
                        # DEFAULT
                        case _:
                            terminal.text(text=f"Invalid choice: {choice}", color="red")

            # SIGNED
            case 1:
                import CrashGuardIEEE.asn1.signed as asn1
                decoded, _ = decodeASN1(MESSAGE, asn1Spec=asn1.Ieee1609Dot2Data())
                MANIPULATE = [
                    "< Done",
                    "protocolVersion",
                    "contentType",
                    "payload",
                    "psid",
                    "generationTime",
                    "expiryTime",
                    "signer name",
                    "validity start",
                    "validity duration"
                ]
                manipulating = True
                
                while manipulating:
                    terminal.clear()
                    title = terminal.getASN1Text(obj=decoded)                 
                    choice = terminal.menu(MANIPULATE, title)

                    match choice:
                        # DONE
                        case 1:
                            msg = encodeASN1(decoded)
                            saveMessage(msg)
                            terminal.clear()
                            terminal.text(text="Done manipulating message:")
                            terminal.printASN1(decoded)
                            manipulating = False
                        # PROTOCOL VERSION
                        case 2:
                            terminal.clear()
                            terminal.printASN1(decoded)
                            protocol_version = int(terminal.input(prompt="protocol version: "))
                            decoded['protocolVersion'] = protocol_version
                        # CONTENT TYPE
                        case 3:
                            terminal.clear()
                            terminal.printASN1(decoded)
                            content_type = int(terminal.input(prompt="content type: "))
                            decoded['contentType'] = content_type
                        # PAYLOAD
                        case 4:
                            terminal.clear()
                            terminal.printASN1(decoded)
                            payload = terminal.input(prompt="payload: ")
                            payload_bytes = payload.encode('utf-8')
                            decoded['content']['signedData']['tbsData']['payload']['data'] = payload_bytes
                        # PSID
                        case 5:
                            terminal.clear()
                            terminal.printASN1(decoded)
                            psid = int(terminal.input(prompt="psid: "))
                            decoded['content']['signedData']['tbsData']['headerInfo']['psid'] = psid
                        # GENERATION TIME
                        case 6:
                            terminal.clear()
                            terminal.printASN1(decoded)
                            terminal.textbox(title="operation", items=["add", "subtract"], numbered=True)

                            operation = terminal.input(prompt="> ")
                            amount = terminal.input(prompt="amount: ")

                            operation = int(operation)
                            amount = int(amount)

                            change = -amount if operation == 2 else amount

                            generation_time = decoded['content']['signedData']['tbsData']['headerInfo']['generationTime']
                            decoded['content']['signedData']['tbsData']['headerInfo']['generationTime'] = generation_time + change

                        # EXPIRY TIME
                        case 7:
                            terminal.clear()
                            terminal.printASN1(decoded)
                            terminal.textbox(title="operation", items=["add", "subtract"], numbered=True)

                            operation = terminal.input(prompt="> ")
                            amount = terminal.input(prompt="amount: ")

                            operation = int(operation)
                            amount = int(amount)

                            change = -amount if operation == 2 else amount

                            expiry_time = decoded['content']['signedData']['tbsData']['headerInfo']['expiryTime']
                            decoded['content']['signedData']['tbsData']['headerInfo']['expiryTime'] = expiry_time + change

                        # SIGNER NAME
                        case 8:
                            terminal.clear()
                            terminal.printASN1(decoded)
                            name = terminal.input(prompt="name: ")
                            decoded['content']['signedData']['signer']['certificate']['toBeSignedCert']['id']['name'] = name
                        # VALIDITY START
                        case 9:
                            terminal.clear()
                            terminal.printASN1(decoded)
                            terminal.textbox(title="operation", items=["add", "subtract"], numbered=True)

                            operation = terminal.input(prompt="> ")
                            amount = terminal.input(prompt="amount: ")

                            operation = int(operation)
                            amount = int(amount)

                            change = -amount if operation == 2 else amount

                            start = decoded['content']['signedData']['signer']['certificate']['toBeSignedCert']['validityPeriod']['start']
                            decoded['content']['signedData']['signer']['certificate']['toBeSignedCert']['validityPeriod']['start'] = start + change

                        # VALIDITY DURATION
                        case 10:
                            terminal.clear()
                            terminal.printASN1(decoded)
                            terminal.textbox(title="operation", items=["add", "subtract"], numbered=True)

                            operation = terminal.input(prompt="> ")
                            amount = terminal.input(prompt="amount (hours): ")

                            operation = int(operation)
                            amount = int(amount)

                            change = -amount if operation == 2 else amount

                            duration = decoded['content']['signedData']['signer']['certificate']['toBeSignedCert']['validityPeriod']['duration']['hours']
                            decoded['content']['signedData']['signer']['certificate']['toBeSignedCert']['validityPeriod']['duration']['hours'] = duration + change

                        # DEFAULT
                        case _:
                            terminal.text(text=f"Invalid choice: {choice}", color="red")

            # ENCRYPTED
            case 2:
                import CrashGuardIEEE.asn1.encrypted as asn1
                decoded, _ = decodeASN1(MESSAGE, asn1Spec=asn1.Ieee1609Dot2Data())
                MANIPULATE = [
                    "< Done",
                    "protocolVersion",
                    "contentType",
                    "pskId",
                    "nonce"
                ]
                manipulating = True
                
                while manipulating:
                    terminal.clear()
                    title = terminal.getASN1Text(obj=decoded)                 
                    choice = terminal.menu(MANIPULATE, title)

                    match choice:
                        # DONE
                        case 1:
                            msg = encodeASN1(decoded)
                            saveMessage(msg)
                            terminal.clear()
                            terminal.text(text="Done manipulating message:")
                            terminal.printASN1(decoded)
                            manipulating = False
                        # PROTOCOL VERSION
                        case 2:
                            terminal.clear()
                            terminal.printASN1(decoded)
                            protocol_version = int(terminal.input(prompt="protocol version: "))
                            decoded['protocolVersion'] = protocol_version
                        # CONTENT TYPE
                        case 3:
                            terminal.clear()
                            terminal.printASN1(decoded)
                            content_type = int(terminal.input(prompt="content type: "))
                            decoded['contentType'] = content_type
                        # PSKID
                        case 4:
                            terminal.clear()
                            terminal.printASN1(decoded)
                            digest = hashes.Hash(hashes.SHA256())
                            random = os.urandom(8)
                            digest.update(random)
                            fake_pskId = digest.finalize()[:8]

                            recipients = decoded['content']['encryptedData']['recipients']
                            a = len(recipients)

                            for i in range(a):
                                decoded['content']['encryptedData']['recipients'][i]['pskRecipInfo'] = fake_pskId

                        # NONCE
                        case 5:
                            terminal.clear()
                            terminal.printASN1(decoded)
                            nonce = os.urandom(12)
                            decoded['content']['encryptedData']['ciphertext']['aes128ccm']['nonce'] = nonce
                        # DEFFAULT
                        case _:
                            terminal.text(text=f"Invalid choice: {choice}", color="red")

            # ENVELOPED
            case 3:
                import CrashGuardIEEE.asn1.enveloped as asn1
                decoded, _ = decodeASN1(MESSAGE, asn1Spec=asn1.Ieee1609Dot2Data())
                MANIPULATE = [
                    "< Done",
                    "protocolVersion",
                    "contentType",
                    "pskId",
                    "nonce"
                ]
                manipulating = True
                
                while manipulating:
                    terminal.clear()
                    title = terminal.getASN1Text(obj=decoded)                 
                    choice = terminal.menu(MANIPULATE, title)

                    match choice:
                        # DONE
                        case 1:
                            msg = encodeASN1(decoded)
                            saveMessage(msg)
                            terminal.clear()
                            terminal.text(text="Done manipulating message:")
                            terminal.printASN1(decoded)
                            manipulating = False
                        # PROTOCOL VERSION
                        case 2:
                            terminal.clear()
                            terminal.printASN1(decoded)
                            protocol_version = int(terminal.input(prompt="protocol version: "))
                            decoded['protocolVersion'] = protocol_version
                        # CONTENT TYPE
                        case 3:
                            terminal.clear()
                            terminal.printASN1(decoded)
                            content_type = int(terminal.input(prompt="content type: "))
                            decoded['contentType'] = content_type
                        # PSKID
                        case 4:
                            terminal.clear()
                            terminal.printASN1(decoded)
                            digest = hashes.Hash(hashes.SHA256())
                            random = os.urandom(8)
                            digest.update(random)
                            fake_pskId = digest.finalize()[:8]

                            recipients = decoded['content']['encryptedData']['recipients']
                            a = len(recipients)

                            for i in range(a):
                                decoded['content']['encryptedData']['recipients'][i]['pskRecipInfo'] = fake_pskId

                        # NONCE
                        case 5:
                            terminal.clear()
                            terminal.printASN1(decoded)
                            nonce = os.urandom(12)
                            decoded['content']['encryptedData']['ciphertext']['aes128ccm']['nonce'] = nonce
                        # DEFFAULT
                        case _:
                            terminal.text(text=f"Invalid choice: {choice}", color="red")

            # DEFAULT
            case _:
                terminal.text(text=f"Invalid choice: {choice}", color="red")

def Replay():
    terminal.clear()
    choice = terminal.menu(["Save replay", "Decode replay"])

    match choice:
        # SAVE REPLAY
        case 1:
            saveReplay()
        # LOAD REPLAY
        case 2:
            _decode(message=getReplay())
        # DEFAULT
        case _:
            terminal.text(text=f"Invalid choice type: {choice}!", color="red")

def Spoofing():
    terminal.clear()
    choice = terminal.menu(["signed (ASN.1)", "enveloped (ASN.1)"])
    terminal.clear()

    # Custom input
    payload = terminal.input(prompt="Payload: ")
    if payload == "`": payload = "Pas op! Pijlwagen" # SHORTCUT
    payload_bytes = payload.encode('utf-8')
    terminal.clear()

    terminal.text(text="Generating PSID...")
    random_byte = os.urandom(1)
    PSID = int.from_bytes(random_byte, "big")

    terminal.text(text="Generating private keys...")
    SENDER_PRIVATE_KEY = ec.generate_private_key(ec.SECP256R1())
    ROOT_CA_PRIVATE_KEY = ec.generate_private_key(ec.SECP256R1())

    match choice:
        # SIGNED
        case 1:
            import CrashGuardIEEE.asn1.signed as asn1

            GENERATION_TIME = int(time.time() * 1_000_000)
            EXPIRY_TIME = GENERATION_TIME + 60_000_000 # 60 seconden

            tbs_data = asn1.ToBeSignedData()
            tbs_data['payload'] = asn1.SignedDataPayload()
            tbs_data['payload']['data'] = payload_bytes
            tbs_data['headerInfo'] = asn1.HeaderInfo()
            tbs_data['headerInfo']['psid'] = PSID
            tbs_data['headerInfo']['generationTime'] = GENERATION_TIME
            tbs_data['headerInfo']['expiryTime'] = EXPIRY_TIME

            verify_key = asn1.VerificationKeyIndicator()
            SENDER_PUBLIC_KEY = SENDER_PRIVATE_KEY.public_key()
            numbers = SENDER_PUBLIC_KEY.public_numbers()
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
            cert_signature = ROOT_CA_PRIVATE_KEY.sign(cert_tbs_der, ec.ECDSA(hashes.SHA256()))
            signer['certificate']['signature'] = cert_signature

            signature = asn1.Signature()
            tbs_der = encodeASN1(tbs_data)
            digest = hashes.Hash(hashes.SHA256())
            digest.update(tbs_der)
            hash_value = digest.finalize()
            signature_der = SENDER_PRIVATE_KEY.sign(hash_value, ec.ECDSA(Prehashed(hashes.SHA256())))
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
            ieee_data['contentType'] = 1
            ieee_data['content'] = asn1.Ieee1609Dot2Content()
            ieee_data['content']['signedData'] = signed_data
            
            terminal.printASN1(ieee_data)
            final_bytes = encodeASN1(ieee_data)
            saveMessage(final_bytes)
            
        # ENVELOPED
        case 2:

            terminal.text(text="Generating PSK...")
            PSK = os.urandom(16)

            import CrashGuardIEEE.asn1.enveloped as asn1

            GENERATION_TIME = int(time.time() * 1_000_000)
            EXPIRY_TIME = GENERATION_TIME + 60_000_000 # 60 seconden

            tbs_data = asn1.ToBeSignedData()
            tbs_data['payload'] = asn1.SignedDataPayload()
            tbs_data['payload']['data'] = payload
            tbs_data['headerInfo'] = asn1.HeaderInfo()
            tbs_data['headerInfo']['psid'] = PSID
            tbs_data['headerInfo']['generationTime'] = GENERATION_TIME
            tbs_data['headerInfo']['expiryTime'] = EXPIRY_TIME

            verify_key = asn1.VerificationKeyIndicator()
            SENDER_PUBLIC_KEY = SENDER_PRIVATE_KEY.public_key()
            numbers = SENDER_PUBLIC_KEY.public_numbers()
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
            cert_signature = ROOT_CA_PRIVATE_KEY.sign(cert_tbs_der, ec.ECDSA(hashes.SHA256()))
            signer['certificate']['signature'] = cert_signature

            signature = asn1.Signature()
            tbs_der = encodeASN1(tbs_data)
            digest = hashes.Hash(hashes.SHA256())
            digest.update(tbs_der)
            hash_value = digest.finalize()
            signature_der = SENDER_PRIVATE_KEY.sign(hash_value, ec.ECDSA(Prehashed(hashes.SHA256())))
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
            ieee_data['contentType'] = 3
            ieee_data['content'] = asn1.Ieee1609Dot2Content()
            ieee_data['content']['encryptedData'] = enc_data

            terminal.printASN1(ieee_data)
            final_bytes = encodeASN1(ieee_data)
            saveMessage(final_bytes)

        # DEFAULT
        case _:
            terminal.text(text=f"Invalid choice type: {choice}!", color="red")
    
    terminal.text(text="Spoofing message opgeslagen!")

def Keys():
    terminal.clear()
    choice = terminal.menu(["Root CA Keys", "Sender Keys", "Psk (pre shared key)"])

    match choice:
        # ROOT CA KEYS
        case 1:
            createRootCAKeys()
            terminal.text(text="Root CA Keys aangepast. Probeer nu het bericht te decoden.")
        # SENDER KEYS
        case 2:
            createSenderKeys
            terminal.text(text="Sender Keys aangepast. Probeer nu het bericht te decoden.")
        # PSK
        case 3:
            createPSK()
            terminal.text(text="PSK aangepast. Probeer nu het bericht te decoden.")
        case _:
            terminal.text(text=f"Invalid choice type: {choice}!", color="red")
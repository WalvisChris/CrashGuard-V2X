from CrashGuardIEEE import MESSAGE, terminal, createPSK, createRootCAKeys, createSenderKeys, saveMessage, saveReplay, getReplay
from CrashGuardIEEE.timer import *
from main import _decode
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
                    "Done",
                    "protocolVersion",
                    "contentType",
                    "payload"
                ]
                manipulating = True
                
                while manipulating:
                    terminal.clear()
                    terminal.printASN1(decoded)                    
                    terminal.textbox(title="Manipulate (unsecure)", items=MANIPULATE, numbered=True)
                    choice = int(terminal.input(prompt="> "))

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
                    "Done",
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
                    terminal.printASN1(decoded)                    
                    terminal.textbox(title="Manipulate (signed)", items=MANIPULATE, numbered=True)
                    choice = int(terminal.input(prompt="> "))

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
                            decoded['content']['signedData']['tbsData']['payload']['data'] = payload_bytes
                        # PSID
                        case 5:
                            psid = int(terminal.input(prompt="psid: "))
                            decoded['content']['signedData']['tbsData']['headerInfo']['psid'] = psid
                        # GENERATION TIME
                        case 6:
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
                            name = terminal.input(prompt="name: ")
                            decoded['content']['signedData']['signer']['certificate']['toBeSignedCert']['id']['name'] = name
                        # VALIDITY START
                        case 9:
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
                    "Done",
                    "protocolVersion",
                    "contentType",
                    "pskId",
                    "nonce"
                ]
                manipulating = True
                
                while manipulating:
                    terminal.clear()
                    terminal.printASN1(decoded)                    
                    terminal.textbox(title="Manipulate (encrypted)", items=MANIPULATE, numbered=True)
                    choice = int(terminal.input(prompt="> "))

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
                        # PSKID
                        case 4:
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
                    "Done",
                    "protocolVersion",
                    "contentType",
                    "pskId",
                    "nonce"
                ]
                manipulating = True
                
                while manipulating:
                    terminal.clear()
                    terminal.printASN1(decoded)                    
                    terminal.textbox(title="Manipulate (enveloped)", items=MANIPULATE, numbered=True)
                    choice = int(terminal.input(prompt="> "))

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
                        # PSKID
                        case 4:
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
    terminal.textbox(title=("Choice"), items=["Save replay", "Decode replay"], numbered=True)
    choice = int(terminal.input(prompt="> "))

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

def Keys():
    terminal.clear()
    terminal.textbox(title=("Choice"), items=["Root CA Keys", "Sender Keys", "Psk (pre shared key)"], numbered=True)
    choice = int(terminal.input(prompt="> "))

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
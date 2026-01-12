from CrashGuardIEEE import MESSAGE, terminal, createPSK, createRootCAKeys, createSenderKeys, saveMessage
from pyasn1.codec.der.encoder import encode as encodeASN1 
from pyasn1.codec.der.decoder import decode as decodeASN1
from pyasn1.type import univ

def Time():
    pass

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
                MANIPULATE = ["Done", "protocolVersion", "contentType", "payload"]
                manipulating = True
                
                while manipulating:
                    terminal.clear()
                    terminal.printASN1(decoded)                    
                    terminal.textbox(title="Manipulate", items=MANIPULATE, numbered=True)
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
                            decoded['content']['unsecureData'] = payload
                        # DEFAULT
                        case _:
                            terminal.text(text=f"Invalid choice: {choice}", color="red")

            # SIGNED
            case 1:
                import CrashGuardIEEE.asn1.signed as asn1
                decoded, _ = decodeASN1(MESSAGE, asn1Spec=asn1.Ieee1609Dot2Data())
                MANIPULATE = ["Done", "protocolVersion", "contentType"]
                manipulating = True
                
                while manipulating:
                    terminal.clear()
                    terminal.printASN1(decoded)                    
                    terminal.textbox(title="Manipulate", items=MANIPULATE, numbered=True)
                    choice = int(terminal.input(prompt="> "))

                    match choice:
                        case 1:
                            msg = encodeASN1(decoded)
                            saveMessage(msg)
                            terminal.clear()
                            terminal.text(text="Done manipulating message:")
                            terminal.printASN1(decoded)
                            manipulating = False
                        case _:
                            terminal.text(text=f"Invalid choice: {choice}", color="red")

            # ENCRYPTED
            case 2:
                import CrashGuardIEEE.asn1.encrypted as asn1
                decoded, _ = decodeASN1(MESSAGE, asn1Spec=asn1.Ieee1609Dot2Data())
                MANIPULATE = ["Done", "protocolVersion", "contentType"]
                manipulating = True
                
                while manipulating:
                    terminal.clear()
                    terminal.printASN1(decoded)                    
                    terminal.textbox(title="Manipulate", items=MANIPULATE, numbered=True)
                    choice = int(terminal.input(prompt="> "))

                    match choice:
                        case 1:
                            msg = encodeASN1(decoded)
                            saveMessage(msg)
                            terminal.clear()
                            terminal.text(text="Done manipulating message:")
                            terminal.printASN1(decoded)
                            manipulating = False
                        case _:
                            terminal.text(text=f"Invalid choice: {choice}", color="red")

            # ENVELOPED
            case 3:
                import CrashGuardIEEE.asn1.enveloped as asn1
                decoded, _ = decodeASN1(MESSAGE, asn1Spec=asn1.Ieee1609Dot2Data())
                MANIPULATE = ["Done", "protocolVersion", "contentType"]
                manipulating = True
                
                while manipulating:
                    terminal.clear()
                    terminal.printASN1(decoded)                    
                    terminal.textbox(title="Manipulate", items=MANIPULATE, numbered=True)
                    choice = int(terminal.input(prompt="> "))

                    match choice:
                        case 1:
                            msg = encodeASN1(decoded)
                            saveMessage(msg)
                            terminal.clear()
                            terminal.text(text="Done manipulating message:")
                            terminal.printASN1(decoded)
                            manipulating = False
                        case _:
                            terminal.text(text=f"Invalid choice: {choice}", color="red")

            # DEFAULT
            case _:
                terminal.text(text=f"Invalid choice: {choice}", color="red")

def Replay():
    pass

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
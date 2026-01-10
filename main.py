from CrashGuardIEEE import encoder, decoder, tester, terminal, MESSAGE, saveMessage
from pyasn1.codec.der.decoder import decode as decodeASN1
from pyasn1.type import univ
from CrashGuardIEEE.timer import *

CONTENT_TYPES = ["unsecure", "signed", "encrypted", "enveloped"]
CHOICES = ["encode", "decode", "testing"]
TESTING_CHOICES = ["Time - Encoding", "Time - Decoding", "Time", "MITM", "Replay", "Fake Credentials"]

def main():
    terminal.clear()
    terminal.textbox(title=("Choice"), items=CHOICES, numbered=True)
    choice = int(terminal.input(prompt="> "))
    terminal.clear()

    match choice:
        # ENCODE
        case 1: _encode()            
        # DECODE
        case 2: _decode()
        # TESTING
        case 3: _testing()
        # DEFAULT
        case _: terminal.text(text=f"Invalid choice type: {choice}!", color="red")

def _encode(timer: Timer | None = None):
    payload = terminal.input(prompt="payload: ")
    terminal.empty()

    terminal.textbox(title=(f"payload: {payload}"), title_color="cyan", items=CONTENT_TYPES, numbered=True)
    content_type = int(terminal.input(prompt="> "))
    terminal.clear()

    payload_bytes = payload.encode('utf-8')
    match content_type:
        case 1:
            unsecureMessage = encoder.encode_unsecure(payload=payload_bytes, timer=timer)
            saveMessage(unsecureMessage)
        case 2: 
            signedMessage = encoder.encode_signed(payload=payload_bytes, timer=timer)
            saveMessage(signedMessage)
        case 3: 
            encryptedMessage = encoder.encode_encrypted(payload=payload_bytes, timer=timer)
            saveMessage(encryptedMessage)
        case 4:
            envelopedMessage = encoder.encode_enveloped(payload=payload_bytes, timer=timer)
            saveMessage(envelopedMessage)
        case _:
            terminal.text(text=f"Invalid content type: {content_type}", color="red")

def _decode(timer: Timer | None = None):
    terminal.clear()
    if MESSAGE == None: terminal.text(text="No message to decode!", color="red")
    else:
        top_level, _ = decodeASN1(MESSAGE, asn1Spec=univ.Sequence())
        content_type = int(top_level[1])
        match content_type:
            case 0:
                terminal.text(text="Found contentType: 0 - unsecure")
                decoder.decode_unsecure(payload=MESSAGE, timer=timer)
            case 1:
                terminal.text(text="Found contentType: 1 - signed")
                decoder.decode_signed(payload=MESSAGE, timer=timer)
            case 2:
                terminal.text(text="Found contentType: 2 - encrypted")
                decoder.decode_encrypted(payload=MESSAGE, timer=timer)
            case 3:
                terminal.text(text="Found contentType: 3 - enveloped")
                decoder.decode_enveloped(payload=MESSAGE, timer=timer)
            case _:
                terminal.text(text=f"Invalid content type: {content_type}!", color="red")

def _testing():
    terminal.clear()
    terminal.textbox(title=("Choice"), items=TESTING_CHOICES, numbered=True)
    choice = int(terminal.input(prompt="> "))
    terminal.clear()

    match choice:
        # Time - Encoding
        case 1:
            newTimer = Timer()
            _encode(timer=newTimer)
            terminal.logTimes(newTimer.timestamps, newTimer.total)
        # Time - Decoding
        case 2:
            newTimer = Timer()
            _decode(timer=newTimer)
            terminal.logTimes(newTimer.timestamps, newTimer.total)
        # Time
        case 3: tester.Time()
        # MITM
        case 4: tester.MITM()
        # Replay
        case 5: tester.Replay()
        # Fake Credentials
        case 6: tester.FakeCredentials()
        # DEFAULT
        case _: terminal.text(text=f"Invalid choice type: {choice}!", color="red")

if __name__ == "__main__":
    main()
"""
Dit document is het hoofdzakelijk script waarmee de simulatie gerunt wordt.
Het verzorgd het start menu en koppelt alle functies en waardes aan elkaar.
"""

# Eerst importeren we alle open source libraries voor o.a. cryptografische funties en alle functies en waardes vanuit CrashGuardIeee
from CrashGuardIEEE import encoder, decoder, tester, terminal, MESSAGE, saveMessage, Visualizer
from pyasn1.codec.der.decoder import decode as decodeASN1
from pyasn1.type import univ
from CrashGuardIEEE.timer import *

# We definieren een paar lijsten om hier later een keuze menu mee te maken
CONTENT_TYPES = ["unsecure (ASN.1)", "signed (ASN.1)", "encrypted (ASN.1)", "enveloped (ASN.1)"]
CHOICES = ["encode", "decode", "testing", "visualize"]
TESTING_CHOICES = ["Latency (Encoding)", "Latency (Decoding)", "MITM", "Replay", "Spoofing", "Keys"]

"""
de functie 'main' runt als eerst en is de start van de simulatie. Hier wordt de keuze gemaakt voor welke tool gebruikt gaat worden
"""
def main():
    terminal.clear()
    choice = terminal.menu(CHOICES)
    terminal.clear()

    match choice:
        # Keuze: encode - start de encoder
        case 1: _encode()            
        # Keuze: decode - start de decoder
        case 2: _decode(MESSAGE)
        # Keuze: testing - start de tester
        case 3: _testing()
        # Keuze: visualize - start de visualizer
        case 4: _visualize()
        # Geef error bij ongeldige keuze
        case _: terminal.text(text=f"Invalid choice type: {choice}!", color="red")

"""
de functie '_encode' geeft een keuze menu voordat de encoder wordt gestart. Hier wordt de payload en het content type gekozen.
Het is mogelijk om een Timer mee te geven als parameter, wat er voor zorgt dat het een snelheids meting wordt gelogd.
"""
def _encode(timer: Timer | None = None):
    payload = terminal.input(prompt="payload: ") # payload wordt gevraagd aan gebruiker
    if payload == "`" or payload == "": payload = "Pas op! Pijlwagen" # default payload als er niets wordt gekozen
    payload_bytes = payload.encode('utf-8') # payload word omgezet naar bytes

    # keuze menu om het content type te kiezen
    terminal.empty()
    title = terminal.simpleTitle(f"Payload: {payload}")
    content_type = terminal.menu(CONTENT_TYPES, title)
    terminal.empty()

    match content_type:
        # keuze: unsecure - start encoder.encode_unsecure met de payload
        case 1:
            unsecureMessage = encoder.encode_unsecure(payload=payload_bytes, timer=timer)
            saveMessage(unsecureMessage) # slaat het ingepakt bericht op in het bestand
        # keuze: signed - start encoder.encode_signed met de payload
        case 2: 
            signedMessage = encoder.encode_signed(payload=payload_bytes, timer=timer)
            saveMessage(signedMessage) # slaat het ingepakt bericht op in het bestand
        # keuze: encrypted - start encoder.encode_encrypted met de payload
        case 3: 
            encryptedMessage = encoder.encode_encrypted(payload=payload_bytes, timer=timer)
            saveMessage(encryptedMessage) # slaat het ingepakt bericht op in het bestand
        # keuze: enveloped - start encoder.encode_enveloped met de payload
        case 4:
            envelopedMessage = encoder.encode_enveloped(payload=payload_bytes, timer=timer)
            saveMessage(envelopedMessage) # slaat het ingepakt bericht op in het bestand
        # Geef error bij ongeldige keuze
        case _:
            terminal.text(text=f"Invalid content type: {content_type}", color="red")

"""
de functie '_decode' onderzoekt het content type van het ontvangen bericht voordat de decoder wordt gestart.
"""
def _decode(message: bytes, timer: Timer | None = None):
    terminal.clear()
    if message == None: terminal.text(text="No message to decode!", color="red") # error als er geen opgeslagen bericht is
    else:
        # pak alleen de eerste laag uit om te zien wat het content type
        top_level, _ = decodeASN1(message, asn1Spec=univ.Sequence())
        content_type = int(top_level[1])
        match content_type:
            # content type: unsecure - decode de payload als unsecure data
            case 0:
                terminal.text(text="Found contentType: 0 - unsecure")
                decoder.decode_unsecure(payload=message, timer=timer)
            # content type: signed - decode de payload als signed data
            case 1:
                terminal.text(text="Found contentType: 1 - signed")
                decoder.decode_signed(payload=message, timer=timer)
            # content type: encrypted - decode de payload als encrypted data
            case 2:
                terminal.text(text="Found contentType: 2 - encrypted")
                decoder.decode_encrypted(payload=message, timer=timer)
            # content type: enveloped - decode de payload als enevloped data
            case 3:
                terminal.text(text="Found contentType: 3 - enveloped")
                decoder.decode_enveloped(payload=message, timer=timer)
            # Geef error bij ongeldige keuze
            case _:
                terminal.text(text=f"Invalid content type: {content_type}!", color="red")

"""
de functie '_testing' geeft een keuze menu voordat de tester wordt gestart. Hier wordt de keuze gemaatk voor de testing tool.
"""
def _testing():
    # keuze menu voor testing tools
    terminal.clear()
    choice = terminal.menu(TESTING_CHOICES)
    terminal.clear()

    match choice:
        # keuze: Latency (Encoding) - start de encoder met een Timer
        case 1:
            newTimer = Timer()
            _encode(timer=newTimer)
            terminal.logTimes(newTimer.timestamps, newTimer.total)
        # keuze: Latency (Decoding) - start de decoder met een Timer
        case 2:
            newTimer = Timer()
            _decode(timer=newTimer)
            terminal.logTimes(newTimer.timestamps, newTimer.total)
        # keuze: MITM - start de tester.MITM
        case 3: tester.MITM()
        # keuze: Replay - start de tester.Replay
        case 4: tester.Replay()
        # Keuze: Spoofing - start de tester.Spoofing
        case 5: tester.Spoofing()
        # Keuze: Keys - start de tester.Keys()
        case 6: tester.Keys()
        # Geef error bij ongeldige keuze
        case _: terminal.text(text=f"Invalid choice type: {choice}!", color="red")

"""
de functie '_visualize' start de visualisatie.
"""
def _visualize():
    terminal.text(text="Visualizer will be openend in another window.")
    window = Visualizer() # verwijs naar de code in CrashGuardIEEE.Visualizer.visuals.py
    window.start()

# Start functie main als het programma wordt gestart
if __name__ == "__main__":
    main()
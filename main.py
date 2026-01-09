from CrashGuardIEEE import encoder, decoder, terminal

# Content Types
CONTENT_TYPES = ["unsecure", "signed", "encrypted", "enveloped"]

# Terminal
terminal.clear()
payload = terminal.input(prompt="payload: ")
terminal.empty()
terminal.textbox(title=(f"payload: {payload}"), title_color="cyan", items=CONTENT_TYPES, numbered=True)
contentType = int(terminal.input(prompt="> "))
terminal.clear()

# IEEE messages
payload_bytes = payload.encode('utf-8')
match contentType:
    case 1:
        unsecureMessage = encoder.encode_unsecure(payload=payload_bytes)
    case 2:
        signedMessage = encoder.encode_signed(payload=payload_bytes)
    case 3:
        encryptedMessage = encoder.encode_encrypted(payload=payload_bytes)
    case 4:
        envelopedMessage = encoder.encode_enveloped(payload=payload_bytes)
    case _:
        terminal.text(text=f"Invalid content type: {contentType}", text_color="red")
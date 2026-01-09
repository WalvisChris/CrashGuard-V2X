from CrashGuardIEEE import encoder, decoder, terminal, MESSAGE, saveMessage

# Content Types
CONTENT_TYPES = ["unsecure", "signed", "encrypted", "enveloped"]

def main():
    # Terminal
    terminal.clear()

    terminal.textbox(title=("Choice"), items=["encode", "decode"], numbered=True)
    choice = int(terminal.input(prompt="> "))
    terminal.clear()

    match choice:
        case 1:
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
                    saveMessage(unsecureMessage)
                case 2: 
                    signedMessage = encoder.encode_signed(payload=payload_bytes)
                    saveMessage(signedMessage)
                case 3: 
                    encryptedMessage = encoder.encode_encrypted(payload=payload_bytes)
                    saveMessage(encryptedMessage)
                case 4:
                    envelopedMessage = encoder.encode_enveloped(payload=payload_bytes)
                    saveMessage(envelopedMessage)
                case _:
                    terminal.text(text=f"Invalid content type: {contentType}", color="red")
        case 2:
            terminal.clear()
            if MESSAGE == None: terminal.text(text="No message to decode!", color="red")
            else: decoder.decode(MESSAGE)
        case _:
            terminal.text(text=f"Invalid choice type: {choice}!", color="red")

if __name__ == "__main__":
    main()
from CrashGuardIEEE import MESSAGE, terminal, createPSK, createRootCAKeys, createSenderKeys

def Time():
    pass

def MITM():
    pass

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
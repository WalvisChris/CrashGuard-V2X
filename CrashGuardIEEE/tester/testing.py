from CrashGuardIEEE import MESSAGE, terminal, createKeys, createPSK

def Time():
    pass

def MITM():
    pass

def Replay():
    pass

def Keys():
    terminal.clear()
    terminal.textbox(title=("Choice"), items=["Private Key", "Psk (pre shared key)"], numbered=True)
    choice = int(terminal.input(prompt="> "))

    match choice:
        # PRIVATE KEY
        case 1:
            createKeys()
            terminal.text(text="Keys aangepast. Probeer nu het bericht te decoden.")
        # PSK
        case 2:
            createPSK()
            terminal.text(text="PSK aangepast. Probeer nu het bericht te decoden.")
        case _:
            terminal.text(text=f"Invalid choice type: {choice}!", color="red")
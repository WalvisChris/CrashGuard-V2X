# CrashGuard V2X IEEE 1609.2 Python simulatie  
In deze simulatie wordt de IEEE 1609.2 standaard, als standaard voor het beveiligen van waarschuwing vanaf Pijlwagens naar voertuigen, gesimuleerd, getest en gevisualiseerd.  

- Met de **encoder** kun je berichten vanaf de Pijlwagen inpakken en versturen.  
- Met de **decoder** kun je berichten bij de auto ontvangen en uitpakken.  
- Met de **tester** kun je de veiligheid en validatie van de standaard testen.  
- Met de **Visualizer** kun je zien hoe voertuigen in de praktijk op deze berichten reageren.  

# Gebruik  
Download de laatste release. Voor Future Mobility Networks is dit `v3.0 - FMN IEEE`. Om de simulatie te gebruiken moet het bestand `main.py` worden geopent met Python (versie 3.12.4). Na iedere actie dient `main.py` opnieuw gestart te worden. Wanneer je een actie wilt stoppen kun je `ctrl+c` klikken om het programma te stoppen.  

# Technisch  
De IEEE standaard definieert meerder content types. Wij simuleren de volgende:  

**1. unsecure data:** bevat alleen de waarschuwing.  

**2. signed data:** het bericht wordt gesigneerd (SHA-256, ECDSA, Pijlwagen private key) en er wordt een ondertekend (SHA256, ECDSA, Root CA private key) certificaat meegestuurd.  

**3. encrypted data:** de waarschuwing wordt geencrypt (AES-128 CCM, PSK).  

**4. enveloped data:** de signed data wordt geencrypt (AES-128 CCM, PSK).  

# Meerwaarde?  
- Door het bestuderen van deze simulatie wordt de workflow van de IEEE 1609.2 standaard helder en is te zien welke stappen nodig zijn om aan deze standaard te voldoen. Zo kom je erachter:
    - Welke **sleutels** zijn nodig?  
    - Wie beheert de **Public Key Infrastructure**?  
    - Wie beheert de **Certificate chain**?  
    - Welke encryptiestandaarden en hashfuncties worden aangeraden?  
    - Hoe weet het voertuig waar de Pijlwagen staat?  
    - Kan het bericht over onveilige netwerken verstuurd worden?  
- Met de testing tools is te zien dat de IEEE standaard het bericht volkomen veilig maakt (mits het juiste content type is gekozen), zodat deze gegarandeerd veilig aankomt en is beschermd tegen mogelijk aanvallen, zoals MitM, spoofing en replay attacks.  

# Caveats  
Bij deze simulatie zijn de volgende topics niet getest:  
- IEEE bericht versturen van Pijlwagen naar voertuig over een **4G/5G netwerk**.  
- IEEE 1609.2 V2X communicatie op de testlocatie bij Future Mobility Park.  
- IEEE bericht versturen vanaf meerdere Pijlwagens naar meerdere voertuigen.  
- IEEE standaard programmeren in een **OBU/RSU** programmeertaal (zoals C/C++).  
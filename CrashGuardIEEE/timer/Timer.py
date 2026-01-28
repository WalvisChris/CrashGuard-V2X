"""Dit script bevat alle code voor bijhouden van een Timer voor het in- en uitpakken"""
# als eerst importeren we een library om tijd te meten
import time

"""De class 'Timer' functioneert als een Timer die kan worden aangemaakt en meegegeven aan de encoder en decoder"""
class Timer:
    # definieer waardes van een timer
    def __init__(self):
        self.start_time = None
        self.end_time = None
        self.total = None
        self.last_timestamp = None
        self.timestamps = []
    
    # zet de timer op 0:00 en start hem
    def startTimer(self):
        now = time.perf_counter()
        self.start_time = now
        self.last_timestamp = now

    # stop de timer
    def stopTimer(self):
        now = time.perf_counter()
        self.end_time = now
        self.total = (now - self.start_time) * 1000 # milliseconden
    
    # geeft de tijd terug sinds het starten
    def getTime(self):
        if self.start_time is None:
            return None
        return (time.perf_counter() - self.start_time) * 1000 # milliseconden
    
    # voegt een timestamp toe aan een lijst van timestamps met een label/beschrijving
    def setTimeStamp(self, label=""):
        if self.last_timestamp is None:
            return None
        
        now = time.perf_counter()
        delta = now - self.last_timestamp
        self.last_timestamp = now
        t = delta * 1000 # milliseconden
        self.timestamps.append((t, label))
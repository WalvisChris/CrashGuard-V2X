import time

class Timer:
    def __init__(self):
        self.start_time = None
        self.last_timestamp = None
        self.timestamps = []
        self.startTimer()
    
    def startTimer(self):
        now = time.perf_counter()
        self.start_time = now
        self.last_timestamp = now
    
    def getTime(self):
        if self.start_time is None:
            return None
        return (time.perf_counter() - self.start_time) * 1000 # milliseconden
    
    def setTimeStamp(self, label=""):
        if self.last_timestamp is None:
            return None
        
        now = time.perf_counter()
        delta = now - self.last_timestamp
        self.last_timestamp = now
        t = delta * 1000 # milliseconden
        return (t, label)
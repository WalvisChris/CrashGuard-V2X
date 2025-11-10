#!/usr/bin/env python3
import socket
import time

HOST = "192.168.1.31"  # PC IP
PORT = 5001
DEVICE_NAME = "EV3-1"

while True:
    try:
        print("setting up connection...")
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.connect((HOST, PORT))
        sock.sendall(DEVICE_NAME.encode("utf-8"))
        sock.close()
        print("Sent device name:", DEVICE_NAME)
    except Exception as e:
        print("Error:", e)
    time.sleep(5)

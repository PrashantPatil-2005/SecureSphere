import socket
import sys

target = 'api-server'
print(f"Scanning {target}...")

for p in range(20, 50):
    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(0.1)
        res = s.connect_ex((target, p))
        s.close()
    except:
        pass
print("Scan complete.")

#Team 04 UNP Network Monitor (python)
#Christiaan Obbink, Salar Darwish, Ka Yue Sin
#Packet sniffer used to monitor network traffic
#For Linux (tested in Ubuntu)- Sniffs all incoming and outgoing packets
#!/usr/bin/python

import socket               # Import socket module

s = socket.socket()         # Create a socket object
host = '192.168.56.101' # Get local machine name
port = 12345                # Reserve a port for your service.

s.connect((host, port))
print s.recv(1024)
s.close                     # Close the socket when done

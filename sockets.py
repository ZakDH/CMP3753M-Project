import codecs
import socket
import codecs
import time

# defining the address to our drone
HOST = '192.168.1.1'
PORT = 5252

# defining a socket object for TCP protocol
sv = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
# connecting to the drone
sv.connect((HOST, PORT))

# sending "ON Mode" command, and adapting it to UDP by choosing socket.SOCK_DGRAM
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect((HOST, 5013))

# first three commands are sequential 
cmd = '6680808080010199' #take off - land 
cmd1 = '6680808080020299' #take off - land
cmd2 = '6680808080030399' #take off - land 
cmd3 = '6680808080000099' #hover - continuous
cmd4 = '6680808080040499' #emergency land

tcpconnect0 = '01010210' #app launch 1
tcpconnect1 = '0e01afe0' #continous between other tcp commands
tcpconnect2='54494d4520323032322d30352d31302032313a33343a33330501c0500f01aff00d01d0d01b00c0b102010320' #app started 2
tcpconnect3='02010320' #click drone button 3
tcpconnect4 = '1b01c0b1' #drone connect 5
tcpconnect5 = '1b00c0b1' #drone disconnect 4

packets =[tcpconnect0, tcpconnect2, tcpconnect3, tcpconnect4]

# # looping packets and printing the hexadecimal response
for packet in packets:
    sv.send(codecs.decode(packet, 'hex'))
    print(codecs.encode(sv.recv(1024), 'hex'))
    print('\n--------\n')

i = 0
while True:  
    sv.send(codecs.decode(tcpconnect1, 'hex'))
    s.send(codecs.decode(cmd, 'hex'))
    time.sleep(1)
import codecs
import socket
import time

# defining the address to our drone
HOST = '192.168.1.1'
PORT = 5252

# sending "ON Mode" command, and adapting it to UDP by choosing socket.SOCK_DGRAM
s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
s.connect((HOST, 5013))
print("connected")

cmd = '6680808080010199' #take off
cmd1 = '6680808080040499' #land
test = 'test'
while True:  
    s.send(codecs.decode(cmd, 'hex'))
    time.sleep(.5)
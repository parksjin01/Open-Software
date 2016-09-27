import socket

sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
sock.connect(('192.168.0.122', 9876))
while True:
    print sock.recv(1024)
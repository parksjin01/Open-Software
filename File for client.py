import socket

def select_victim():
    router_ip=raw_input('Input router IP')
    return router_ip

sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
router_addr=select_victim()
sock.connect(('192.168.0.2', 9875))
sock.sendall(router_addr)
while True:
    a=sock.recv(20)
    if a:
        print a
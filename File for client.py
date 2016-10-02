#모듈호출 부분
import socket
from PyQt4 import QtGui, QtCore
import sys

#팝업을 띄우기 위한 클래스 생성
class SystemTrayIcon(QtGui.QSystemTrayIcon):
    def __init__(self, parent=None):
        QtGui.QSystemTrayIcon.__init__(self, parent)
        self.setIcon(QtGui.QIcon('myicon.png'))

        self.menu = QtGui.QMenu(parent)
        exitAction = self.menu.addAction("Exit")
        exitAction.triggered.connect(self.exitActionFunc)
        self.setContextMenu(self.menu)

    def exitActionFunc(self):
        #recover function here
        sys.exit()

    def warn(self, ip_address):
        self.showMessage("Warning","%s is dangerous, Don't go there!" %ip_address)

#라우터 IP를 입력받는다.
def select_victim():
    router_ip=raw_input('Input router IP')
    return router_ip

#클라이언트용 소켓을 생성하여 서버와 통신한다.
sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
router_addr=select_victim()
sock.connect(('192.168.0.2', 9875))
sock.sendall(router_addr)

#서버에서 받은 위험한 ip 정보를 팝업의 형태로 띄워준다.
app = QtGui.QApplication([])
tray = SystemTrayIcon()
QtGui.QSystemTrayIcon.show(tray)
while True:
    a=sock.recv(20)
    if a:
        tray.warn(a)

app.exec_()

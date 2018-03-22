from scapy.all import *
import os
from cStringIO import StringIO
import sys




count=0
mystdout = StringIO()

def get_GW():
    """send echo pck when the ttl is 0 so when it arrive to the GW he send me back a TTL ERROR (ICMP MESSEGE)
    , the src is the GW"""
    p = sr1(IP(dst="google.com", ttl=0) / ICMP() / "XXXXXXXXXXX",verbose=0)
    return p.src

def find_mac_by_ip(ip):
    result = sr1(ARP(op=ARP.who_has, pdst=ip),verbose=0)
    return result.hwsrc #The mac

def duplicate_ip_with_same_mac():
    pass

def arp_gw(macGW,ipGW):
    # rstrip: remove \n from the string
    mac=os.popen("arp | awk '{if ($1==\"%s\") print $3}'" % (ipGW)).read().rstrip()
    if mac!=macGW:
        count+=1
    return

def percente_is_at(pcks):
    pkts = sniff(count=9,filter='arp',timeout=20)
    #change the stdout for get the sniff result
    old_stdout = sys.stdout
    sys.stdout = mystdout
    pkts.show()
    #return the stdout as usual
    sys.stdout = old_stdout
    countIsAt=len(mystdout.getvalue().split('is at')) - 1 #getvalue return string of the output (p.show())
    if(countIsAt>6):
        count+=1
    # examine mystdout.getvalue()


def main():
    global count
    ipGW=get_GW()
    macGW=find_mac_by_ip(ipGW)
    while True:
        pass

if __name__=="__main__":
    main()
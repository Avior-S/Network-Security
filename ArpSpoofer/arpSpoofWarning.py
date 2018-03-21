from scapy.all import *
import os


def get_GW():
    """send echo pck when the ttl is 0 so when it arrive to the GW he send me back a TTL ERROR (ICMP MESSEGE)
    , the src is the GW"""
    p = sr1(IP(dst="8.8.8.8", ttl=0) / ICMP() / "XXXXXXXXXXX",verbose=0)
    return p.src

def find_mac_by_ip(ip):
    result = sr1(ARP(op=ARP.who_has, pdst=ip),verbose=0)
    return result.hwsrc #The mac

def duplicate_ip_with_same_mac():
    pass

def arp_gw(macGW,ipGW):
    #rstrip: remove \n from the string
    mac=os.popen("arp | awk '{if ($1==\"%s\") print $3}'" % (ipGW)).read().rstrip()
    return mac!=macGW


def percente_is_at(pcks):
    pass


def main():
    ipGW=get_GW()
    macGW=find_mac_by_ip(ipGW)
    while True:
        pass

if __name__=="__main__":
    main()
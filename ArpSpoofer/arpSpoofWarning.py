from scapy.all import *
import os


def get_GW():
    """send echo pck when the ttl is 0 so when it arrive to the GW he send me back a TTL ERROR (ICMP MESSEGE)
    , the src is the GW"""
    p = sr1(IP(dst="8.8.8.8", ttl=0) / ICMP() / "XXXXXXXXXXX",verbose=0)
    return p.src

def duplicate_ip_with_same_mac():
    pass

def arp_gw(ipGW):
    os.system('arp | awk `$1=={} print {$3}`', ipGW)

def percente_is_at(pcks):
    pass


def main():
    ipGW=get_GW()
    while True:
        pass

if __name__=="__main__":
    main()
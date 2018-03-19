import argparse
import sys
from scapy.all import *


def findMyIP():
    """ I send echo pck when the ttl is 0 so when it arrive to the GW he send me back a TTL ERROR (ICMP MESSEGE)
    , the dst is our ip.
    """
    # I write IP and not domain cause i want to save time.
    p = sr1(IP(dst="8.8.8.8", ttl=0) / ICMP() / "XXXXXXXXXXX",verbose=0,timeout=5) #verbose = withuot output
    return p.dst
def getGW():
    """I send echo pck when the ttl is 0 so when it arrive to the GW he send me back a TTL ERROR (ICMP MESSEGE)
    , the src is the GW"""
    p = sr1(IP(dst="8.8.8.8", ttl=0) / ICMP() / "XXXXXXXXXXX",verbose=0)
    return p.src


parser = argparse.ArgumentParser(description='Process some arguments.')
parser.add_argument("-i" ,"--iface", type=str, default='enp0s3',
                    help="The attack interface")
parser.add_argument("-s" ,"--src", type=str, default=findMyIP(),
                    help="The address you want for the attacker")
parser.add_argument("-d" ,"--delay", type=float, default=1,
                    help="Delay (in seconds) between messages")
parser.add_argument("-gw" , type=str, default=getGW(),
                    help="should GW be attacked as well")
parser.add_argument("-t" ,"--target", type=str,
                    help="The attacked ip")

args = parser.parse_args()



def main():
    print(args.iface)
    print args

if __name__=="__main__":
    main()
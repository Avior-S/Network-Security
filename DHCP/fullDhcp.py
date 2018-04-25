from scapy.all import *

conf.checkIPaddr=False

#def configuration(conf_dic):
# configuration
localiface = 'enp0s3'
requestMAC = 'fc:4d:d4:33:2f:41'
myhostname='vektor'
localmac = get_if_hwaddr(localiface)
localmacraw = requestMAC.replace(':','').decode('hex')

# craft DHCP DISCOVER
dhcp_discover = Ether(src=localmac, dst='ff:ff:ff:ff:ff:ff')/IP(src='0.0.0.0', dst='255.255.255.255')/UDP(dport=67, sport=68)/BOOTP(chaddr=localmacraw,xid=RandInt())/DHCP(options=[('message-type', 'discover'), 'end'])
print dhcp_discover.display()

# send discover, wait for reply
sendp(dhcp_discover,iface=localiface)
x=sniff(count=1,filter='udp and (port 67 or 68)')[0]
dhcp_offer=x.display()

# craft DHCP REQUEST from DHCP OFFER
myip=dhcp_offer[BOOTP].yiaddr
sip=dhcp_offer[BOOTP].siaddr
xid=dhcp_offer[BOOTP].xid
print("xid: ",xid)
dhcp_request = Ether(src=localmac,dst="ff:ff:ff:ff:ff:ff")/IP(src="0.0.0.0",dst="255.255.255.255")/UDP(sport=68,dport=67)/BOOTP(chaddr=localmacraw,xid=xid)/DHCP(options=[("message-type","request"),("server_id",sip),("requested_addr",myip),("hostname",myhostname),("param_req_list","pad"),"end"])
print dhcp_request.display()

# send request, wait for ack
sendp(dhcp_discover,iface=localiface)
dhcp_ack=sniff(count=1,filter='udp and (port 67 or 68)')[0]

print dhcp_ack.display()
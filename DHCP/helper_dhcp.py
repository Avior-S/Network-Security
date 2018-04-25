from scapy.all import *
#get hardware information of our pentest machine
fam, hw = get_if_raw_hwaddr(conf.iface)
op_dic={}
# Define a callback function for when DHCP packets are received
def dhcp_dic(resp):
#    print "DHCP offer from : " +resp[Ether].src
#    print "To : " +resp[Ether].dst

    #Display DHCP options :
    op_dic['src_mac']=resp[Ether].src
    op_dic['dst_mac']=resp[Ether].dst
    for opt in resp[DHCP].options:
        if opt == 'end': # This option indicate the end of a DHCP options area in DHCP message packets
            break
        elif opt == 'pad': #This option is used as byte padding to cause subsequent option records to align on a word boundary.
            break
        print opt  #DHCP option
        op_dic[opt[0]]=opt[1]

def build_dhcp_discover():
    # Forge our DHCP request
    ether = Ether(dst='ff:ff:ff:ff:ff:ff')
    ip = IP(src='0.0.0.0', dst='255.255.255.255')
    udp = UDP(sport=68, dport=67)
    bootp = BOOTP(chaddr=hw)
    dhcp = DHCP(options=[("message-type","discover")])

    return ether/ip/udp/bootp/dhcp

def get_dhcp_options():
   # x=srp1(build_dhcp_discover())
    sendp(build_dhcp_discover())
    sniff(prn=dhcp_dic, filter='udp and (port 67 or 68)', count=1,store=1)
    return op_dic
if __name__=="__main__":
    get_dhcp_options()
# Send the DHCP request
#sendp(dhcp_request)

# Set a filter and sniff for any DHCP packets
#sniff(prn=dhcp_print, filter='udp and (port 67 or 68)', store=1)
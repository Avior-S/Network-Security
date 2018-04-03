from scapy.all import *

from cStringIO import StringIO
import sys
import subprocess




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
    global count
    proc = subprocess.Popen(["arp | awk '{print $3}'"], stdout=subprocess.PIPE, shell=True)
    (out, err) = proc.communicate()
    if err!=None:
        print err
  #      return
    macsInNet=out.split('\n')
    if len(macsInNet) != len(set(macsInNet)):
        count+=1
        return "Duplicate ip with the same mac"
    return ""

def arp_gw(macGW,ipGW):
    # rstrip: remove \n from the string
    global count
    proc = subprocess.Popen(["arp | awk '{if ($1==\"%s\") print $3}'" % (ipGW)], stdout=subprocess.PIPE, shell=True)
    (out, err) = proc.communicate()
    if err!=None:
        print err
 #       return ""
    mac=out.rstrip()
    if mac!=macGW:
        count+=1
        return "Mac gateway change"
    return ""

def percente_is_at():
    global count
    pkts = sniff(count=7,filter='arp',timeout=16)
    #change the stdout for get the sniff result
    old_stdout = sys.stdout
    mystdout.reset()
    sys.stdout = mystdout

    pkts.show()
    #return the stdout as usual
    sys.stdout = old_stdout
    countIsAt=len(mystdout.getvalue().split('is at')) - 1 #getvalue return string of the output (p.show())
    if(countIsAt>4):
        count+=1
        return "A lot arp response send"
    # examine mystdout.getvalue()
    return ""


def main():
    global count
    ipGW=get_GW()
    macGW=find_mac_by_ip(ipGW)
    while True:
        p = percente_is_at()
        a = arp_gw(macGW,ipGW)
        d = duplicate_ip_with_same_mac()
        if count>=2:
            print "Warning, Attacked"
            print a, '\n', p, '\n', d
            choice=input("Do use want to scan again? \npress 1 else press 0\n")
            if choice!=1:
                break
        else:
            print "your computer is clear from arpSpoofing attack \n count = ", count
        count=0
if __name__=="__main__":
    main()
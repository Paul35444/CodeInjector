#!/usr/bin/env python
import netfilterqueue
import scapy.all as scapy
import re

def set_load(packet, load):
    packet[scapy.Raw].load = load
#del and scapy will auto complete for each modified packet
    del scapy_packet[scapy.IP].len
    del scapy_packet[scapy.IP].chksum
    del scapy_packet[scapy.TCP].chksum
    return packet

def process_packet(packet):
    scapy_packet = scapy.IP(packet.get_payload())
#check packets RAW layer
    if scapy_packet.haslayer(scapy.RAW):
#check packets destination port for 80 (http) REQUESTS
        if scapy_packet[scapy.TCP].dport == 80:
            print("[+] Request")
#regex to replace the first arg with a empty string
            modified_load = re.sub("Accept-Encoding:.*?\\r\\n", "", scapy_packet[scapy.Raw].load)
#check packets source port for 80 (http) RESPONSES
        elif scapy_packet[scapy.TCP].sport == 80:
            print("[+] Response")
            print(scapy_packet.show())
    packet.accept()

#create instance of queue
queue = netfilterqueue.NetfilterQueue()
#bind queue to queue num 0 and callback to func process_packet
queue.bind(0, process_packet)
queue.run

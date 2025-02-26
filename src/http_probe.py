import scapy.all as scapy
from scapy.layers.http import *
from scapy.layers.inet import TCP, IP



def probe(ip,port):
    response = scapy.sr1(IP(dst=ip) / TCP(dport=port, flags="S"), timeout=1, verbose=False)
    response.show()

    client = HTTP_Client()
    http_response = client.request(f"http://{ip}:{port}")
    client.close()

    http_response.show()

    return response


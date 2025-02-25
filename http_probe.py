import scapy.all as scapy
import argparse
from scapy.layers import http
from scapy.layers.http import *
from scapy.layers.inet import TCP, IP





def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', dest='target', help='Target IP Address/Addresses')
    parser.add_argument('-p', '--ports', dest='port', type=int, help='specify specific port to scan, default 1-1000')
    ip_selections = parser.parse_args()

    if not ip_selections.target:
        parser.error('Please specify a target IP --help for more information')

    return ip_selections

def probe(ip,port):
    response = scapy.sr1(IP(dst=ip) / TCP(dport=port, flags="S"), timeout=1, verbose=False)
    response.show()

    client = HTTP_Client()
    http_response = client.request(f"http://{ip}:{port}")
    client.close()

    http_response.show()

    return response



options = get_args()

probe_output = probe(options.target, options.port)
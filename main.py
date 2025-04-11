import argparse
import sys
import socket
from colorama import Fore, init
from src.banner import banner
from src.arp_scanner import scan, scan_ports
from src.http_probe import probe
from src.target import get_target

#reset colors after line defining them
init(autoreset=True)



#display results for ARP
def display_arp_result(result):
    print(Fore.GREEN + "-----------------------------------\nIP Address\tMAC Address\n-----------------------------------")
    for i in result:
        print("{}\t{}".format(i["ip"], i["mac"]))

#display results for Scan
def display_port_scan_result(ports):
    print(Fore.GREEN + "-----------------------------------\n Ports \n-----------------------------------")
    for x in ports:
        print(Fore.CYAN + f"Open ports for {x}: {ports[x]['open']}")
        for p in ports[x]['open']:
            if p == 80:
                parsing = input(Fore.RED + "Port 80 found. Probe HTTP? Y/n:  ")
                if parsing == "Y":
                    print(Fore.GREEN + f"--------------------\n Probing port {p} \n--------------------")
                    try:
                        probe(x,p)
                    except ValueError:
                        print(Fore.YELLOW + f"URL for {x} port {p} won't resolve")
                        pass
                else:
                    pass






#Start running the program
banner()

#Get the IP target range
new_options = get_target()

#ARP scan on target ip/ip range
scanned_output = scan(new_options)
display_arp_result(scanned_output)

#scan ports
scanned_ports = scan_ports()
display_port_scan_result(scanned_ports)


import argparse
from colorama import Fore, init



from src.banner import banner
from src.arp_scanner import scan, scan_ports
from src.http_probe import probe

#reset colors after line defining them
init(autoreset=True)



def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', dest='target', help='Target IP Address/Addresses')
    parser.add_argument('-p', '--ports', dest='ports', type=int, help='specify specific port/port range to scan')
    ip_selections = parser.parse_args()

    if not ip_selections.target:
        parser.error('Please specify a target IP --help for more information')

    return ip_selections


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
                print(Fore.GREEN + f"--------------------\n Probing port {p} \n--------------------")
                try:
                    probe(x,p)
                except ValueError:
                    print(Fore.YELLOW + f"URL for {x} port {p} won't resolve")
                    pass




banner()

#getting command line args
options = get_args()

#ARP scan on target ip/ip range
scanned_output = scan(options.target)
display_arp_result(scanned_output)

#Port scan on results from ARP scan - no args yet
#next step, take in an options.ports arg and parse to select custom port range, pass a arg to this def
#scan_ports(options.ports)
#can also wrap this in an if so it only runs if there is a -p flag

if options.ports:
    scanned_ports = scan_ports(options.ports)
    display_port_scan_result(scanned_ports)


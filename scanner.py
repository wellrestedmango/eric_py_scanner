import scapy.all as scapy
import argparse
from scapy.layers.inet import TCP, IP


#making this variable global to prevent dropping packets when doing ARP twice
ip_only = []

#get ip from command line arguments
def get_args():
    parser = argparse.ArgumentParser()
    parser.add_argument('-t', '--target', dest='target', help='Target IP Address/Addresses')
    parser.add_argument('-p', '--ports', dest='ports', action='store_true', help='specify specific port to scan, default 1-1000')
    ip_selections = parser.parse_args()

    if not ip_selections.target:
        parser.error('Please specify a target IP --help for more information')

    return ip_selections

#create frames and send to network
def scan(ip):
    #pdst is the scrapy destination ip address, sets that target ip in our arp frame
    arp_req_frame = scapy.ARP(pdst = ip)

    #creates and ethernet frame to the broadcast MAC of ff:::::ff
    broadcast_ether_frame = scapy.Ether(dst = 'ff:ff:ff:ff:ff:ff')
    #combines our broadcast frame and our ARP frame
    broadcast_ether_arp_req_frame = broadcast_ether_frame/arp_req_frame

    #srp takes a frame as an argument and broadcasts it
    #returnes a tuple of answered and unanswered requests - for now we only need the answers hence the [0]
    #later builds will take the whole tuple to filter out unopened ports, dropping the [0]
    answered_list = scapy.srp(broadcast_ether_arp_req_frame, timeout=1, verbose=True)[0]

    print(answered_list)

    #taking just the IP portion of this to scan well-known ports - needed for port scan
    for i in range(0, len(answered_list)):
        ip_only.append(answered_list[i][1].psrc)

    #takes answered list, adds ip and mac of the responding devices [1]
    result = []
    for i in range(0,len(answered_list)):
        client_dict = {
            "ip":answered_list[i][1].psrc,
            "mac":answered_list[i][1].hwsrc
        }
        result.append(client_dict)
    return result

def scan_ports(arg_ports):
    # setting the well-known ports as default and scanning them - will make this an arg in the future
    #take ports as an arg and parse - if else to the default range of 1001
    ports = range(1, 100)

    #setting an empty dict for results
    ip_dict = {}

    #only scanning the results from the ARP scan
    for ip in ip_only:
        print(f'----------------------\nScanning {ip}\n----------------------')

        #setting lists for results - only handling open for now, but saving rest for later use
        open_ports = []
        closed_ports = []
        no_response_ports = []

        #go through each port
        for port in ports:

            #sending a scrapy request - saving result
            response = scapy.sr(IP(dst=ip) / TCP(dport=port, flags="S"), timeout=1, verbose=False)[0]
            if response:
                for sent, received in response:
                    if received.haslayer(TCP) and received[TCP].flags == 18:
                        open_ports.append(port)
                    elif received.haslayer(TCP) and received[TCP].flags == 20:
                        closed_ports.append(port)
            else:
                no_response_ports.append(port)

        #saving a dict that will be nested into the used dict
        temp_port_dict = {
            "open": open_ports,
            "closed": closed_ports,
            "no response": no_response_ports
        }

        #nesting temp dict into main dict - can call results by ip, and then by result for future functions
        ip_dict[ip] = temp_port_dict
    return ip_dict

#display results for ARP
def display_arp_result(result):
    print("-----------------------------------\nIP Address\tMAC Address\n-----------------------------------")
    for i in result:
        print("{}\t{}".format(i["ip"], i["mac"]))

#display results for Scan
def display_port_scan_result(ports):
    print("-----------------------------------\n Ports \n-----------------------------------")
    for x in ports:
        print(f"Open ports for {x}: \n {ports[x]['open']}")

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


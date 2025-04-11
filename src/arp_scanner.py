import scapy.all as scapy
from scapy.layers.inet import TCP, IP
from colorama import Fore, init

init(autoreset=True)



#making this variable global to prevent dropping packets when doing ARP twice
ip_only = []

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

def scan_ports():
    # setting the well-known ports as default and scanning them - will make this an arg in the future
    #take ports as an arg and parse - if else to the default range of 1001
    ports = range(1, 100)

    #setting an empty dict for results
    ip_dict = {}

    #only scanning the results from the ARP scan
    for ip in ip_only:
        print(Fore.GREEN + f'----------------------\nScanning {ip}\n----------------------')

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




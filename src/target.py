import colorama
import socket
from colorama import Fore


def get_target():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip_range = input(Fore.GREEN + f'Your IP address is {s.getsockname()[0]}. Use /24 for the network? Y/n:  ')
    if ip_range == "Y":
        ip_split = s.getsockname()[0].split(".")
        returning_ip = f'{ip_split[0]}.{ip_split[1]}.{ip_split[2]}.1/24'
        return returning_ip
    else:
        desired_range = input(Fore.GREEN + "Enter your desired IP range:  ")
        return desired_range


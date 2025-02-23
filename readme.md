# Eric's Nmap Clone
This clone of nmap is a personal project to learn more about the functionality that nmap provides.
In addition, it serves the dual purpose of teaching me more about both python and tcp/ip protocols.

This tool is not intended to probe public networks or to conduct any penetration testing


Personal note:

scapy needs sudo permissions, but running as sudo changes user on bash

to save environment variables from current bash and run using this command structure

sudo -E **path to project**/py_scanner/.venv/bin/python3 scanner.py **flags** **iprange**

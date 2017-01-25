#!/usr/bin/env python

import os, argparse, subprocess, re

parser = argparse.ArgumentParser(description=\
"""
Allows user to tell OS to use particular interface to reach an IP address.
Also indicates the MAC address that corresponds to that IP address so it
does not need to perform ARP.
""")

parser.add_argument('iface', type=str, help='The interface to use to reach IP addres')
parser.add_argument('ip', type=str, help='The IP address to reach')
parser.add_argument('mac', type=str, help='The MAC address that corresponds to the IP address')

args = parser.parse_args()

# tell the system how to get to each fake network
os.system('sudo ip route add %s dev %s' % (args.ip, args.iface))

# populate the ARP table entries
os.system('sudo arp -i %s -s %s %s' % (args.iface, args.ip, args.mac))



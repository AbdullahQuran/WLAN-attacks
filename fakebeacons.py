#!/usr/bin/python 

import sys

from scapy.all import *

brdmac = "ff:ff:ff:ff:ff:ff"

bssid = "bb:bb:bb:bb:bb:bb"

pkt = RadioTap() / Dot11(addr1 = brdmac, addr2 = bssid, addr3 = bssid)/Dot11Beacon(cap = 0x1421)/ Dot11Elt (ID=0, info = sys.argv[1])/ Dot11Elt (ID = 1, info = "\0x8c\0x12\0x98\0x24\0x30\0x48\0x60\0x6c") / Dot11Elt (ID=3, info = "\0x01")/ Dot11Elt (ID=5, info = "\0x01\0x02\0x00\0x00")

sendp (pkt, iface = "wlan0", count = int (sys.argv[2]), inter = 0.2)


                                                                                                                                                                              

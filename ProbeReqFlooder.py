#!/usr/bin/env python

from scapy.all import *

brdmac = "ff:ff:ff:ff:ff:ff"

pkt = RadioTap()/Dot11(type=0,subtype=4,addr1=brdmac,addr2=RandMAC(),addr3=brdmac)

sendp(pkt,iface = sys.argv [1], count = int (sys.argv [2]),inter=0.05)

                                                                                                                                                                              

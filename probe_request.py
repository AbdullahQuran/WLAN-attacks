#!/usr/bin/python 

import sys

from scapy.all import *

client = set()
test1 = 0

def PacketHandler(pkt):
	if pkt.haslayer(Dot11ProbeReq):
		if len(pkt.info) > 0:
			global test1
			test1 = pkt.addr2 + '----' + pkt.info 
		if test1 not in client :
			client.add(test1)
			print "New Probe Found:  " + pkt.addr2 + "   "  +  pkt.info


sniff(iface = sys.argv [1], count = int (sys.argv [2]), prn = PacketHandler)


                                                                                                                                                                              

#!/usr/bin/env python

# Name: Pinjectme.py
# Author: KADDOUR BOUMEDIENE
# Purpose: Packet injection
# date of creating: xx/xx/2014

import socket 
import struct 
from random import randint
from sys import argv

def checksum(data):
        s = 0
	n = len(data) % 2
	for i in range(0, len(data)-n, 2):
		s+= ord(data[i]) + (ord(data[i+1]) << 8)
	if n:
		s+= ord(data[i+1])
	while (s >> 16):
		s = (s & 0xFFFF) + (s >> 16)
	s = ~s & 0xffff
	return s

class InjectMe:
	def __init__(self,source, dest, sport,dport):
		##### IP ####
		self.version = 4
		self.ihl = 5
		self.tos = 0
		self.tlen = 0
		self.id = randint(50000, 60000)
		self.flags = 0
		self.offset = 0
		self.ttl = 64
		self.protocol = socket.IPPROTO_TCP
		self.checksum = 0
		self.source = socket.inet_aton(source)
		self.dest = socket.inet_aton(dest)
		##### TCP ####
		self.sport = sport
		self.dport = dport
		self.seq = 0
		self.ack = 0
		self.tcpoffset = 5
		self.reserved = 0
		self.urg = 0
		self.ack = 0
		self.psh = 0
		self.rst = 0
		self.syn = 0
		self.fin = 0
		self.window = socket.htons(1500)
		self.checksum = 0
		self.urgent_pointer = 0
		self.payload = "data to be injected"
		
	def packing_ip_header(self):
		# Packing IP header
		ver_ihl = (self.version << 4) + self.ihl
		flags_offset = (self.flags << 13) + self.offset
		ip_header = struct.pack('!BBHHHBBH4s4s', ver_ihl,
			    self.tos,
		   	  self.id,
			    self.tlen,
			    flags_offset,
			    self.ttl,
			    self.protocol,
			    self.checksum,
			    self.source,
			    self.dest)
		# packing TCP Header
		return ip_header
	def packing_tcp_header(self, srcIP, dstIP):
		data_offset = (self.tcpoffset << 4) + 0
		#flags = self.urg + (self.ack << 5) + (self.psh << 4) + (self.rst << 3) + (self.syn << 2) + (self.fin << 1)
		flags = self.fin + (self.syn << 1) + (self.rst << 2) + (self.psh << 3) + (self.ack << 4) + (self.urg << 5)
		tcp_header = struct.pack('!HHLLBBHHH', 
			     self.sport,
			     self.dport,
			     self.seq,
			     self.ack,
			     data_offset,
			     flags,
			     self.window,
			     self.checksum,
			     self.urgent_pointer)
		
		# Generating Pseudo header to calculate checksum
		SrcIP = srcIP
		DstIP = dstIP
		reserved = 0
		protocol = socket.IPPROTO_TCP
		tlen = len(tcp_header) + len(self.payload)
		pshdr = struct.pack('!4s4sBBH',
			SrcIP,
			DstIP,
			reserved,
			protocol,
			tlen)
		pshdr = pshdr + tcp_header + self.payload
		tcp_checksum = checksum(pshdr)
		tcp_header = struct.pack('!HHLLBBH',
			 self.sport,
			 self.dport,
			 self.seq,
			 self.ack,
			 data_offset,
			 flags,
			 self.window)
		tcp_checksum = struct.pack('H', tcp_checksum)
		urgent_pointer = struct.pack('H', self.urgent_pointer)
		tcp_header = tcp_header + tcp_checksum + urgent_pointer
		return tcp_header


if len(argv) != 4:
	print """
Usage:	
	%s <TCP_FLAG> <Destination_IP> <Dport>
	      """%argv[0]
	exit(1)
sip = '%d.%d.%d.%d'%(randint(1,254),randint(1,254),randint(1,254),randint(1,254))
dip = argv[2]
obj = InjectMe(sip, dip, randint(49151, 65000), int(argv[3]))
given_flag = argv[1]
if given_flag.lower() =='u':
	obj.urg = 1
elif given_flag.lower() =="a":
	obj.ack = 1
elif given_flag.lower() == "p":
	obj.psh = 1
elif given_flag.lower() == "r":
	obj.rst = 1
elif given_flag.lower() == "s":
	obj.syn = 1
elif given_flag.lower() == "f":
	obj.fin = 1
elif given_flag.lower() == "sa" or given_flag.lower() == "as" :
	obj.syn = 1
	obj.ack = 1
elif given_flag.lower() == "x" or given_flag.lower() == "xmas":
	obj.urg = 1
	obj.ack = 1
	obj.psh = 1
	obj.rst = 1
	obj.syn = 1
	obj.fin = 1
else:
	print "No Such Flag"
	exit(1)
	
iphdr = obj.packing_ip_header()
tcphdr = obj.packing_tcp_header(obj.source, obj.dest) 
print "[+] All headers generated"
pkt = iphdr + tcphdr
s = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
s.sendto(pkt,(dip,0))
print "[+] PKT injected :)"


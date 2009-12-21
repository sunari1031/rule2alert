import struct
from binascii import *
from ctypes import create_string_buffer
from scapy.all import *
import sys
import string

class PayloadGenerator:
	pkts = []
	payload = None
	contents = []
	itered = []

	def __init__(self, rule_contents):
		self.contents = rule_contents
		self.payload = None
		self.itered = []

		#These are for crafting packets
		self.src	   = ""
		self.dst	   = ""
		self.sport	 = ""
		self.dport	 = ""
		self.proto	 = ""
		self.flow	  = IP()
		self.handshake = False
		self.packets   = []
		
	def build(self):
		oldc = None
		itered = []
		for c in self.contents:
			if not oldc:
				c.ini = 0
				c.end = len(c.content)
			else:
				c.ini = oldc.end + 1
				c.end = c.ini + len(c.content)

			if c.offset and not oldc:
				c.ini = c.ini + c.offset
				c.end = c.end + c.offset

			if c.offset and oldc:
				# Here we should check for conflicts
				if c.ini < c.offset:
					c.ini = c.offset
					c.end = c.ini + len(c.content)

			if c.distance and oldc:
				if oldc.end + c.distance > c.ini:
					c.ini = oldc.end + c.distance
					c.end = oldc.end + c.distance + len(c.content)

			# Checks
			if c.depth and c.end > c.depth:
				print "Error here depth!" 

			# Checks
			if c.within and c.end > oldc.end + c.within:
				print "Error here within!" 
				
			oldc = c
			itered.append(c)
			print "-> Ini: " + str(c.ini) + " End: " + str(c.end)

		# buffer size
		max = 0
		for c in itered:
			if c.end > max:
				max = c.end

		# perform padding with ' 's (blank spaces)
		padding = ""
		for i in range(0,max):
			padding = padding + " "
		self.payload = create_string_buffer(max)
		struct.pack_into(str(max) + "s", self.payload, 0, padding)

		# write payloads
		for c in itered:
			if not c.negated:
				fmt = str(c.end - c.ini) + "s"
				flag=0
				tmp = ""
				i = 0
				while i < len(c.content):
					if c.content[i]=="|" and (i>0 and c.content[i-1]!='\\' or i==0) and flag == 0:
						flag = 1
						i = i + 1
						continue

					if c.content[i]=="|" and i>0 and c.content[i-1]!='\\' and flag == 1:
						flag = 0
						i = i + 1
						continue

					if c.content[i]==" " and flag == 1:
						i = i + 1
						continue

					if flag == 1:
						tmp = tmp + a2b_hex(c.content[i:i+2])
						i = i + 1
					else:
						tmp = tmp + c.content[i]
						
					i = i + 1

				struct.pack_into(fmt, self.payload, c.ini, tmp)

		self.itered = itered
		return self.payload

	def build_handshake(self):
		client_isn = 1932
		server_isn = 1059

		syn = Ether()/IP(src=self.flow.src, dst=self.flow.dst)/TCP(flags="S", sport=self.proto.sport, dport=self.proto.dport, seq=client_isn)

		synack = Ether()/IP(src=self.flow.dst, dst=self.flow.src)/TCP(flags="SA", sport=self.proto.dport, dport=self.proto.sport, seq=server_isn, ack=syn.seq+1)

		ack = Ether()/IP(src=self.flow.src, dst=self.flow.dst)/TCP(flags="A", sport=self.proto.sport, dport=self.proto.dport, seq=syn.seq+1, ack=synack.seq+1)
	
		self.packets.append(syn)
		self.packets.append(synack)
		self.packets.append(ack)

	def get_seqack(self):
		if len(self.packets) == 0:
			return 0

		seq = self.packets[-1].seq
		ack = self.packets[-1].ack

		return seq,ack

	def parseComm(self, sports, dports, snort_vars):
		if self.proto == "tcp":
			self.proto = TCP()
		elif self.proto == "udp":
			self.proto = UDP()
		#If the source is using CIDR notiation
		#Just pick the first IP in the subnet
		if self.src.find("/") != -1:
			self.src = self.src.split("/")[0]
			self.src = "%s.%s" % (self.src[:self.src.rfind(".")],"1")
		#Same for the dst
		if self.dst.find("/") != -1:
			self.dst = self.dst.split("/")[0]
			self.dst = "%s.%s" % (self.dst[:self.dst.rfind(".")],"1")
		#If any on either src or dst just use any IP
		if self.src == "any":
			self.src = "1.1.1.1"
		if self.dst == "any":
			self.dst = "1.1.1.1"

		self.flow.src = self.src
		self.flow.dst = self.dst

		#Do the same type of thing for ports
		if sports[1:] in snort_vars:
			self.sport = snort_vars[sports[1:]]
		elif sports == "any":
			self.sport = "9001"
		else:
			self.sport = sports

		if dports[1:] in snort_vars:
			self.dport = snort_vars[dports[1:]]
		elif dports == "any":
			self.dport = "9001"
		else:
			self.dport = dports

		self.proto.sport = int(self.sport)
		self.proto.dport = int(self.dport)
		
	def write_packets(self, pcap):
		wrpcap(self.packets, pcap)

	def hexPrint(self):
		str = ''
		str = str + "-------- Hex Payload Start ----------\n"
		for i in range(0,len(self.payload)):
			str = str + " " + hexlify(self.payload[i])
			if i > 0 and (i + 1) % 4 == 0:
				str = str + " "
			if i > 0 and (i + 1) % 8 == 0:
				str = str + "\n"
		str = str + "\n--------- Hex Payload End -----------\n"
		return str

	def asciiPrint(self):
		str = ''
		str = str + "-------- Ascii Payload Start ----------\n"
		for i in range(0,len(self.payload)):
			c = self.payload.raw[i]
			if c in string.printable:
				str = str + c
			else:
				str = str + "\\x" + hexlify(c)
		str = str + "\n--------- Ascii Payload End -----------\n"
		return str
			
	def PrintOffsets(self):
		print " Start		End"		
		if self.itered == []:
			return
		for c in self.itered:
			print "%05s  %10s" % (str(c.ini), str(c.end))

	def __str__(self):
		if self.payload == None:
			print "No payload to print"
			return ""

		printable = 1
		for i in range(0,len(self.payload)):
			if not self.payload[i] in string.printable:
				printable = 0
		if printable:
			return self.asciiPrint()
		else:
		   return self.hexPrint()

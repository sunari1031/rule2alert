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

	def __init__(self, rule_contents, flow):
		self.contents = rule_contents
		self.payload = None
		self.flow = flow
		self.itered = []

		#These are for crafting packets
		self.src	   = ""
		self.dst	   = ""
		self.sport	   = ""
		self.dport	   = ""
		self.proto	   = ""
		self.protocol  = ""
		self.ip  	   = IP()
		self.handshake = False
		self.packets   = []
		
	def build(self):
		if self.flow.established:
			self.build_handshake()

		oldc = None
		itered = []
		for c in self.contents:
			if not oldc:
				c.ini = 0
				#c.end = len(c.content)
				c.end = len(c.payload)
			else:
				c.ini = oldc.end + 1
				#c.end = c.ini + len(c.content)
				c.end = c.ini + len(c.payload)

			if c.offset and not oldc:
				c.ini = c.ini + c.offset
				c.end = c.end + c.offset

			if c.offset and oldc:
				# Here we should check for conflicts
				if c.ini < c.offset:
					c.ini = c.offset
					#c.end = c.ini + len(c.content)
					c.end = c.ini + len(c.payload)

			if c.distance and oldc:
				if oldc.end + c.distance > c.ini:
					c.ini = oldc.end + c.distance
					#c.end = oldc.end + c.distance + len(c.content)
					c.end = oldc.end + c.distance + len(c.payload)

			# Checks
			if c.depth and c.end > c.depth:
				print "Error here depth!" 

			# Checks
			if c.within and c.end > oldc.end + c.within:
				print "Error here within!" 
				
			oldc = c
			itered.append(c)
			#print "-> Ini: " + str(c.ini) + " End: " + str(c.end)

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
			fmt = str(c.end - c.ini) + "s"
			struct.pack_into(fmt, self.payload, c.ini, c.payload)

		self.itered = itered

		self.build_packet(self.payload.raw)

		return self.payload

	def build_packet(self, payload):

		source_ip   = self.ip.src
		source_port = self.protocol.sport
		dest_ip	    = self.ip.dst
		dest_port   = self.protocol.dport

		#Set flow
		if self.flow is not None:
			if self.flow.to_server or self.flow.from_client:
				source_ip = self.ip.src
				source_port = self.protocol.sport
				dest_ip = self.ip.dst
				dest_port = self.protocol.dport
			elif self.flow.to_client or self.flow.from_server:
				source_ip = self.ip.dst
				source_port = self.protocol.dport
				dest_ip = self.ip.src
				dest_port = self.protocol.sport

		if self.proto == "tcp":
			seq_num, ack_num = self.get_seqack()
			if seq_num is None:
				seq_num = 9001
				ack_num = 9002

			p = Ether()/IP(src=source_ip, dst=dest_ip)/TCP(flags="PA", sport=source_port, dport=dest_port, seq=seq_num, ack=ack_num)/payload

			rst = Ether()/IP(src=source_ip, dst=dest_ip)/TCP(flags="R", sport=source_port, dport=dest_port)

		elif self.proto == "udp":
			p = Ether()/IP(src=source_ip, dst=dest_ip)/UDP(sport=source_port, dport=dest_port)/payload


		self.packets.append(p)


	def build_handshake(self):
		client_isn = 1932
		server_isn = 1059

		syn = Ether()/IP(src=self.ip.src, dst=self.ip.dst)/TCP(flags="S", sport=self.protocol.sport, dport=self.protocol.dport, seq=client_isn)

		synack = Ether()/IP(src=self.ip.dst, dst=self.ip.src)/TCP(flags="SA", sport=self.protocol.dport, dport=self.protocol.sport, seq=server_isn, ack=syn.seq+1)

		ack = Ether()/IP(src=self.ip.src, dst=self.ip.dst)/TCP(flags="A", sport=self.protocol.sport, dport=self.protocol.dport, seq=syn.seq+1, ack=synack.seq+1)
	
		self.packets.append(syn)
		self.packets.append(synack)
		self.packets.append(ack)

	def get_seqack(self):
		if len(self.packets) == 0:
			return None,None

		seq = self.packets[-1].seq
		ack = self.packets[-1].ack

		return seq,ack

	def parseComm(self, sports, dports, snort_vars):
		if self.proto == "tcp":
			self.protocol = TCP()
		elif self.proto == "udp":
			self.protocol = UDP()
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

		self.ip.src = self.src
		self.ip.dst = self.dst

		#Do the same type of thing for ports
		if sports[1:] in snort_vars:
			self.sport = snort_vars[sports[1:]]
		elif sports == "any":
			self.sport = "9001"
		elif sports.find(":") != -1:
			self.sport = sports.split(":")[0]
		else:
			self.sport = sports

		if dports[1:] in snort_vars:
			self.dport = snort_vars[dports[1:]]
		elif dports == "any":
			self.dport = "9001"
		elif dports.find(":") != -1:
			self.dport = dports.split(":")[0]
		else:
			self.dport = dports

		self.protocol.sport = int(self.sport)
		self.protocol.dport = int(self.dport)
		
	def write_packets(self, pcap):
		wrpcap(pcap, self.packets)

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

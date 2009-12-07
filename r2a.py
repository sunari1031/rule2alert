#!/usr/bin/python
from Parser.RuleParser import *
from scapy.all import *
from optparse import OptionParser
import os,sys

class r2a:
	#Initial function sets global variables used throughout the class
	#Calls parseConf and loadRules to parse the snort configuration
	#file as well as load in the snort rules to generate packets
	def __init__(self, options):
		#Command line options
		self.options = options
		#Snort conf variables
		self.snort_vars = self.parseConf(self.options.snort_conf)
		#Snort rules
		self.rules = self.loadRules(self.options.rule_file)
		#IP Source Address
		self.source = ""
		#Source Port
		self.sport = ""
		#IP Destination Address
		self.dest = ""
		#Destination Port
		self.dport = ""
		#Transport Layer Protocol
		self.proto = ""
		#Set generic IP layer
		self.flow = IP()

	def main(self):
		#Go through each snort rule
		for snort_rule in self.rules:
			snort_rule = snort_rule.strip()
			#Parse the snort rule using the snort parser
			r = Rule(snort_rule)
	
			self.source = self.snort_vars[r.rawsources[1:]]
			self.dest   = self.snort_vars[r.rawdestinations[1:]]
			self.proto  = r.proto

			#Set the transport layer based on the protocol
			if self.proto == "tcp":
				self.proto = TCP()
			elif self.proto == "udp":
				self.proto = UDP()

			#Sets flow options based on snort alert
			self.parseComm(r.rawsrcports, r.rawdesports)
			
			handshake = self.handshake()

			print "%s:%s -> %s:%s" % (self.source, self.sport, self.dest, self.dport)

			print r

	#Make TCP Handshake based off snort rule direction and src/dst attributes
	def handshake(self):
		#Client ISN
		client_isn = 1932
		#Server ISN
		server_isn = 1059

		#Create the SYN Packet sent from the client to the server
		syn = Ether()/IP(src=self.flow.src, dst=self.flow.dst)/TCP(flags="S", sport=self.proto.sport, dport=self.proto.dport, seq=client_isn)

		#Create the SYN/ACK Packet returned from the server
		syn_ack = Ether()/IP(src=self.flow.dst, dst=self.flow.src)/TCP(flags="SA", sport=self.proto.dport, dport=self.proto.sport, seq=server_isn, ack=syn.seq+1)
		
		#Create the ACK returned from the client
		ack = Ether()/IP(src=self.flow.src, dst=self.flow.dst)/TCP(flags="A", sport=self.proto.sport, dport=self.proto.dport, seq=syn.seq+1, ack=syn_ack.seq+1)

		handshake = [syn, syn_ack, ack]
		for p in handshake:
			print p.summary()

		return handshake
	
	#Parses the snort rule configuration to generate a flow
	#Which is later used in the packet generation
	def parseComm(self, sports, dports):
		#If the source is using CIDR notiation
		#Just pick the first IP in the subnet
		if self.source.find("/") != -1:
			self.source = self.source.split("/")[0]
			self.source = "%s.%s" % (self.source[:self.source.rfind(".")],"1")
		#Same for the dst
		if self.dest.find("/") != -1:
			self.dest = self.dest.split("/")[0]
			self.dest = "%s.%s" % (self.dest[:self.dest.rfind(".")],"1")
		#If any on either src or dst just use any IP
		if self.source == "any":
			self.source = "1.1.1.1"
		if self.dest == "any":
			self.dest = "1.1.1.1"

		self.flow.src = self.source
		self.flow.dst = self.dest

		#Do the same type of thing for ports
		if sports[1:] in self.snort_vars:
			self.sport = self.snort_vars[sports[1:]]
		elif sports == "any":
			self.sport = "9001"
		else:
			self.sport = sports

		if dports[1:] in self.snort_vars:
			self.dport = self.snort_vars[dports[1:]]
		else:
			self.dport = dports

		self.proto.sport = int(self.sport)
		self.proto.dport = int(self.dport)

		
	#Reads in the rule file specified by the user
	def loadRules(self, rule_file):
		f = open(rule_file, 'r')
		rules = f.read().splitlines()
		f.close()

		return rules

	#Parses the snort configuration for all variables
	#This is mostly used to grab variables such as
	#$HOME_NET and $EXTERNAL_NET
	def parseConf(self, snort_conf):
		f = open(snort_conf, 'r')
		conf = f.read().splitlines()
		f.close()

		snort_vars = {}

		for line in conf:
			if line.startswith("var"):
				var, data = line[4:].split(" ")
				if data[1:] in snort_vars:
					data = snort_vars[data[1:]]
				snort_vars[var] = data
			elif line.startswith("portvar"):
				var, data = line[8:].split(" ")
				if data[1:] in snort_vars:
					data = snort_vars[data[1:]]
				snort_vars[var] = data
				

		return snort_vars
				
				

	
#Parses arguments that are passed in through the cli
def parseArgs():
	usage = "usage: ./r2a.py -f rule_file -c snort_config -w pcap"
	parser = OptionParser(usage)
	
	parser.add_option("-f", help="Read in snort rule file", action="store", type="string", dest="rule_file")
	parser.add_option("-c", help="Read in snort configuration file", action="store", type="string", dest="snort_conf")
	parser.add_option("-w", help="Name of pcap file", action="store", type="string", dest="pcap")

	(options, args) = parser.parse_args(sys.argv)

	r = r2a(options)
	r.main()

if __name__ == "__main__":
	parseArgs()

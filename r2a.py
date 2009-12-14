#!/usr/bin/python
from Parser.RuleParser import *
from Generator.Payload import *
from optparse import OptionParser
import os,sys
import re

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
		#Packet generator
		#self.ContentGen = ContentGenerator()
		self.ContentGen = ""

	def main(self):
		#Regexp for avoid comments and empty lines
		pcomments = re.compile('^\s*#')
		pemptylines = re.compile('^\s*$')
		rules_loaded = 0
		#Go through each snort rule
		for snort_rule in self.rules:
			snort_rule = snort_rule.strip()
			#Parse the snort rule using the snort parser
			comments = pcomments.search(snort_rule)
			emptylines = pemptylines.search(snort_rule)
			#If it's not a comment or an empty line...
			if not comments and not emptylines:
				try:
					r = Rule(snort_rule)
					self.ContentGen = PayloadGenerator(r.contents)

					self.ContentGen.src = self.snort_vars[r.rawsources[1:]]
					self.ContentGen.dst = self.snort_vars[r.rawdestinations[1:]]
					self.ContentGen.proto  = r.proto

					#Set the transport layer based on the protocol
					if self.ContentGen.proto == "tcp":
						self.ContentGen.proto = TCP()
					elif self.ContentGen.proto == "udp":
						self.ContentGen.proto = UDP()
		
					#Sets flow options based on snort alert
					self.parseComm(r.rawsrcports, r.rawdesports)

					#packets = self.ContentGen.build()
					self.ContentGen.build_handshake()
					
					for p in self.ContentGen.packets:
						print p.summary()
		
					#ContentGen = PayloadGenerator(r.contents)
		
					#payload = ContentGen.build()
		
					#print ContentGen
					rules_loaded = rules_loaded + 1
				except:
					traceback.print_exc()
					print "Parser failed with rule: " + snort_rule
					continue
		print "Loaded "+str(rules_loaded)+" rules succesfully!"

	#Parses the snort rule configuration to generate a flow
	#Which is later used in the packet generation
	def parseComm(self, sports, dports):
		#If the source is using CIDR notiation
		#Just pick the first IP in the subnet
		if self.ContentGen.src.find("/") != -1:
			self.ContentGen.src = self.ContentGen.src.split("/")[0]
			self.ContentGen.src = "%s.%s" % (self.ContentGen.src[:self.ContentGen.src.rfind(".")],"1")
		#Same for the dst
		if self.ContentGen.dst.find("/") != -1:
			self.ContentGen.dst = self.ContentGen.dst.split("/")[0]
			self.ContentGen.dst = "%s.%s" % (self.ContentGen.dst[:self.ContentGen.dst.rfind(".")],"1")
		#If any on either src or dst just use any IP
		if self.ContentGen.src == "any":
			self.ContentGen.src = "1.1.1.1"
		if self.ContentGen.dst == "any":
			self.ContentGen.dst = "1.1.1.1"

		self.ContentGen.flow.src = self.ContentGen.src
		self.ContentGen.flow.dst = self.ContentGen.dst

		#Do the same type of thing for ports
		if sports[1:] in self.snort_vars:
			self.ContentGen.sport = self.snort_vars[sports[1:]]
		elif sports == "any":
			self.ContentGen.sport = "9001"
		else:
			self.ContentGen.sport = sports

		if dports[1:] in self.snort_vars:
			self.ContentGen.dport = self.snort_vars[dports[1:]]
		elif dports == "any":
			self.ContentGen.dport = "9001"
		else:
			self.ContentGen.dport = dports

		self.ContentGen.proto.sport = int(self.ContentGen.sport)
		self.ContentGen.proto.dport = int(self.ContentGen.dport)

		
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

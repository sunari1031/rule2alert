#!/usr/bin/python
from Parser.RuleParser import *
from scapy.all import *
from optparse import OptionParser
import os,sys

class r2a:
	def __init__(self, options):
		self.options = options
		self.snort_vars = self.parseConf(self.options.snort_conf)
		self.rules = self.loadRules(self.options.rule_file)
		self.source = ""
		self.sport = ""
		self.dest = ""
		self.dport = ""
		self.proto = ""
		self.flow = IP()

	def main(self):

		for snort_rule in self.rules:
			snort_rule = snort_rule.strip()
			r = Rule(snort_rule)
	
			self.source = self.snort_vars[r.rawsources[1:]]
			self.dest   = self.snort_vars[r.rawdestinations[1:]]
			self.proto  = r.proto

			if self.proto == "tcp":
				self.proto = TCP()
			elif self.proto == "udp":
				self.proto = UDP()

			print self.source
			print self.dest

			self.parseComm(r.rawsrcports, r.rawdesports)

			print "%s:%s -> %s:%s" % (self.source, self.sport, self.dest, self.dport)

	def parseComm(self, sports, dports):
		if self.source.find("/") != -1:
			self.source = self.source.split("/")[0]
			self.source = "%s.%s" % (self.source[:self.source.rfind(".")],"1")
		if self.dest.find("/") != -1:
			self.dest = self.dest.split("/")[0]
			self.dest = "%s.%s" % (self.dest[:self.dest.rfind(".")],"1")
		if self.source == "any":
			self.source = "1.1.1.1"
		if self.dest == "any":
			self.dest = "1.1.1.1"

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

		

	def loadRules(self, rule_file):
		f = open(rule_file, 'r')
		rules = f.read().splitlines()
		f.close()

		return rules

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

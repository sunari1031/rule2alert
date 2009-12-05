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

	def main(self):

		for snort_rule in self.rules:
			snort_rule = snort_rule.strip()
			r = Rule(snort_rule)

			print r.rawdestinations
			print r.rawsources
		

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

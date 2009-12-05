#!/usr/bin/python
from Parser.RuleParser import *
from scapy.all import *
from optparse import OptionParser
import os,sys

class r2a:
	

	def main(self, options):
		#Parse the snort config
		var = self.parseConf(options.snort_conf)

		#Parse snort rule file
		rules = self.loadRules(options.rule_file)

		for snort_rule in rules:
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
		return 1

	

def parseArgs():
	usage = "usage: ./r2a.py -f rule_file -c snort_config -w pcap"
	parser = OptionParser(usage)
	
	parser.add_option("-f", help="Read in snort rule file", action="store", type="string", dest="rule_file")
	parser.add_option("-c", help="Read in snort configuration file", action="store", type="string", dest="snort_conf")
	parser.add_option("-w", help="Name of pcap file", action="store", type="string", dest="pcap")

	(options, args) = parser.parse_args(sys.argv)

	r = r2a()
	r.main(options)

if __name__ == "__main__":
	parseArgs()

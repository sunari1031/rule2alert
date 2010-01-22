#!/usr/bin/python
from scapy.all import *
from Parser.RuleParser import *
from Parser.SnortConf import *
from Generator.Payload import *
from Generator.TestSnort import *
from optparse import OptionParser
import os,sys
import re
from time import sleep

class r2a:
	#Initial function sets global variables used throughout the class
	#Calls parseConf and loadRules to parse the snort configuration
	#file as well as load in the snort rules to generate packets
	def __init__(self, options):
		#Command line options
		self.options = options
		#Snort conf variables
		self.snort_vars = SnortConf(self.options.snort_conf).parse()
		#Snort rules
		self.rules = self.loadRules(self.options.rule_file)
		#Packet generator
		self.ContentGen = ""
		#List of packets built from rules
		self.packets = []
		#Number of alerts from snort test cases
		self.alerts = 0
		#Number of rules initially loaded
		self.rules_loaded = 0
		#Collection of SIDS loaded
		self.sids = []

	def main(self):
		#Regexp for avoid comments and empty lines
		pcomments = re.compile('^\s*#')
		pemptylines = re.compile('^\s*$')
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
					print "Building Rule: %s" % str(r.sid)
					self.ContentGen = PayloadGenerator(r, self.snort_vars)

					self.ContentGen.build()

					self.sids.append(r.sid)

					for p in self.ContentGen.packets:
					#	print p.summary()
						self.packets.append(p)

					if self.options.hex:
						print "\n" + self.ContentGen.hexPrint()

					self.rules_loaded += 1

					sleep(0.0001)

				except:
					traceback.print_exc()
					#print "Parser failed with rule: " + snort_rule
					print "Parser failed - skipping rule"
					continue
		print "Loaded %d rules succesfully!" % self.rules_loaded

		print "Writing packets to pcap..."
		
		self.write_packets()

		if self.options.testSnort:
			self.test_snort()

	#Reads in the rule file specified by the user
	def loadRules(self, rule_file):
		f = open(rule_file, 'r')
		rules = f.read().splitlines()
		f.close()

		return rules

	def write_packets(self):
		wrpcap(self.options.pcap, self.packets)

	def test_snort(self):
		t = TestSnort(self.options.snort_conf, self.options.pcap, self.sids)
		t.run()

#Parses arguments that are passed in through the cli
def parseArgs():
	usage = "usage: python r2a.py [-vt] -f rule_file -c snort_config -w pcap"
	parser = OptionParser(usage)
	
	parser.add_option("-f", help="Read in snort rule file", action="store", type="string", dest="rule_file")
	parser.add_option("-c", help="Read in snort configuration file", action="store", type="string", dest="snort_conf")
	parser.add_option("-w", help="Name of pcap file", action="store", type="string", dest="pcap")

	parser.add_option("-v", help="Verbose hex output of raw alert", action="store_true", dest="hex")
	parser.add_option("-t", help="Test rule against current snort configuration", action="store_true", dest="testSnort")

	if len(sys.argv) == 1:
		print usage
		sys.exit(0)

	(options, args) = parser.parse_args(sys.argv)

	r = r2a(options)
	r.main()

if __name__ == "__main__":
	parseArgs()

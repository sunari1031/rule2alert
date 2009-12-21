#!/usr/bin/python
from scapy.all import *
from Parser.RuleParser import *
from Parser.SnortConf import *
from Generator.Payload import *
from Generator.TestSnort import *
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
		self.snort_vars = SnortConf(self.options.snort_conf).parse()
		#Snort rules
		self.rules = self.loadRules(self.options.rule_file)
		#Packet generator
		self.ContentGen = ""
		#List of packets built from rules
		self.packets = []
		#Number of alerts from snort test cases
		self.alerts = 0

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

					self.ContentGen.parseComm(r.rawsrcports, r.rawdesports, self.snort_vars)

					self.ContentGen.build_handshake()

					self.ContentGen.build()
					#print self.ContentGen.hexPrint()
					
					for p in self.ContentGen.packets:
						print p.summary()
						self.packets.append(p)
		

					rules_loaded = rules_loaded + 1

					#self.ContentGen.write_packets("test.pcap")

					t = TestSnort(self.options.snort_conf, "test.pcap")
					num = t.run()

					self.alerts += int(num)

				except:
					traceback.print_exc()
					#print "Parser failed with rule: " + snort_rule
					print "Parser failed - skipping rule"
					continue
		print "Loaded "+str(rules_loaded)+" rules succesfully!"

		print "Alerted %s time(s)" % str(self.alerts)
		
		self.write_packets()

	#Reads in the rule file specified by the user
	def loadRules(self, rule_file):
		f = open(rule_file, 'r')
		rules = f.read().splitlines()
		f.close()

		return rules

	def write_packets(self):
		wrpcap(self.options.pcap, self.packets)

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

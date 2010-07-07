#!/usr/bin/python
from scapy.all import *
from Parser.RuleParser import *
from Parser.SnortConf import *
from Generator.Payload import *
from Generator.TestSnort import *
from Generator.TestSuricata import *
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
		if not self.options.snort_conf: 
			if not self.options.extNet or not self.options.homeNet:
				print "If no snort conf, please provide ExtNet and HomeNet variables via command line"
				sys.exit(0)
			else:
				self.snort_vars = SnortConf().default(self.options.extNet, self.options.homeNet)
		else:
			self.snort_vars = SnortConf(self.options.snort_conf).parse()
		if self.options.extNet:
			self.snort_vars["EXTERNAL_NET"] = self.options.extNet
		if self.options.homeNet:
			self.snort_vars["HOME_NET"] = self.options.homeNet
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
		#Association of SID to Packets
		self.sidGroup = {}
		#List of Failed SIDS
		self.failSids = []
		#Used in SID reproduction
		self.count = None
		self.manual = False
		if self.options.manualNum and self.options.manualSid:
			if int(self.options.manualNum) < 1:
				self.manual = False
			else:
				self.manual = True
				self.count = int(self.options.manualNum)

	def main(self):
		#manualCount = 0
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

					if self.manual and str(r.sid) == self.options.manualSid and self.count != 1:
						self.count -= 1
						self.rules.append(snort_rule)
	
					print "Building Rule: %s" % str(r.sid)
					self.ContentGen = PayloadGenerator(r, self.snort_vars)

					if self.ContentGen.notSupported:
						continue

					self.ContentGen.build()

					self.sids.append(r.sid)

					prevLen = len(self.packets)
					numPackets = len(self.ContentGen.packets)
					self.sidGroup[r.sid] = (prevLen, numPackets)

					for p in self.ContentGen.packets:
						self.packets.append(p)

					if self.options.hex:
						print "\n" + self.ContentGen.hexPrint()

					self.rules_loaded += 1

					sleep(0.0001)

				except:
					traceback.print_exc()
					print "Parser failed - skipping rule"
					continue

		print "Loaded %d rules succesfully!" % self.rules_loaded

		
		if self.packets and self.options.pcap:
			print "Writing packets to pcap..."
			self.write_packets()
			print "Finished writing packets"

		if self.options.testSnort and self.options.pcap:
			print "Running snort test..."
			self.test_snort()

		if self.options.testSuricata and self.options.pcap:
			print "Running Suricata test..."
			self.test_suricata()

		if (self.options.testSnort or self.options.testSuricata) and self.options.failStream:
			if not self.failSids: return
			for sid in self.failSids:
				start, length = self.sidGroup[sid]
				end = start + (length-1)
				if length == 1:
					r = self.packets[start]
				elif length > 1:
					r = self.packets[start:start+(length-1)]
				wrpcap("output/failstreams/%s.pcap" % sid, r)

	#Reads in the rule file specified by the user
	def loadRules(self, rule_file):
		f = open(rule_file, 'r')
		rules = f.read().splitlines()
		f.close()

		return rules

	def write_packets(self):
		wrpcap(self.options.pcap, self.packets)

	def test_snort(self):
		t = TestSnort(self.options.pcap, self.sids)
		self.failSids = t.run()

	def test_suricata(self):
		t = TestSuricata(self.options.pcap, self.sids, self.options.rule_file)
		self.failSids = t.run()

#Parses arguments that are passed in through the cli
def parseArgs():
	usage = "usage: python r2a.py [-vt] -f rule_file -c snort_config -w pcap"
	parser = OptionParser(usage)
	
	parser.add_option("-c", help="Read in snort configuration file", action="store", type="string", dest="snort_conf")
	parser.add_option("-f", help="Read in snort rule file", action="store", type="string", dest="rule_file")
	parser.add_option("-F", help="Write failed streams to pcap", action="store_true", dest="failStream")
	parser.add_option("-w", help="Name of pcap file", action="store", type="string", dest="pcap")

	parser.add_option("-v", help="Verbose hex output of raw alert", action="store_true", dest="hex")
	parser.add_option("-t", help="Test rule against current snort configuration", action="store_true", dest="testSnort")
	parser.add_option("-T", help="Test rule against current Suricata configuration", action="store_true", dest="testSuricata")
	parser.add_option("-m", help="Set $HOME_NET IP Address", action="store", type="string", dest="homeNet")
	parser.add_option("-e", help="Set $EXTERNAL_NET IP Address", action="store", type="string", dest="extNet")
	parser.add_option("-s", help="Manual SID Selection", action="store", type="string", dest="manualSid")
	parser.add_option("-n", help="Number of times to alert SID", action="store", type="string", dest="manualNum")

	if len(sys.argv) == 1:
		parser.print_help()
		sys.exit(0)

	(options, args) = parser.parse_args(sys.argv)

	r = r2a(options)
	r.main()

if __name__ == "__main__":
	parseArgs()

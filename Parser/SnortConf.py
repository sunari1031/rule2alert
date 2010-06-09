import os,re

class SnortConf:
	
	def __init__(self, file=None):
		self.conf  = file
		self.vars  = {}
		self.src   = None
		self.dst   = None
		self.sport = None
		self.dport = None

	def default(self, extNet, homeNet):
		self.vars = {
				"HOME_NET": homeNet,
				"EXTERNAL_NET": extNet,
				"DNS_SERVERS": homeNet,
				"SMTP_SERVERS": homeNet,
				"HTTP_SERVERS": homeNet,
				"SQL_SERVERS": homeNet,
				"TELNET_SERVERS": homeNet,
				"FTP_SERVERS": homeNet,
				"SNMP_SERVERS": homeNet,
				"HTTP_PORTS": 80,
				"SSH_PORTS": 22,
				"SHELLCODE_PORTS": 81,
				"ORACLE_PORTS": 1521,
				"FTP_PORTS": 21
			    }

		return self.vars
		
	def parse(self):
		f = open(self.conf, 'r')
		conf = f.read().splitlines()
		f.close()

		for line in conf:
			if line.startswith("var"):
				r = re.search("var\s+(?P<var>[A-Z]+)\s+(?P<data>[\w\[\]\,\$]+)", line)
				if not r: continue
				#var,data = line[4:].split(" ")
				var  = r.group("var")
				data = r.group("data")

				if data[1:] in self.vars:
					data = self.vars[data[1:]]
				self.vars[var] = data
			elif line.startswith("portvar"):
				r = re.search("portvar\s+(?P<var>[A-Z]+)\s+(?P<data>[\d\$\[\]\,]+)", line)
				if not r: continue
				#var, data = line[8:].strip().split(" ")
				var  = r.group("var")
				data = r.group("data")
				#if data.startswith("$") and data[1:] in self.vars:
				if data[1:] in self.vars:
					data = self.vars[data[1:]]
				if data.startswith("!$"):
					data = self.vars[data[2:]]
				elif data.startswith("!"):
					data = int(data[1:]) + 1
				elif data.startswith("$"):
					data = self.vars[data[1:]]

				self.vars[var] = data

	
		return self.vars

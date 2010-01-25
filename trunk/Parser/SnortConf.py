import os

class SnortConf:
	
	def __init__(self, file):
		self.conf  = file
		self.vars  = {}
		self.src   = None
		self.dst   = None
		self.sport = None
		self.dport = None
		
	def parse(self):
		f = open(self.conf, 'r')
		conf = f.read().splitlines()
		f.close()

		for line in conf:
			if line.startswith("var"):
				var,data = line[4:].split(" ")
				if data[1:] in self.vars:
					data = self.vars[data[1:]]
				if data.startswith("!"):
					tmp = self.vars[data[2:]]
					if tmp.startswith("192."):
						data = "10.0.0.1"
					elif tmp.startswith("10."):
						data = "192.168.0.1"
					#data = self.vars[data[2:]]
				self.vars[var] = data
			elif line.startswith("portvar"):
				var, data = line[8:].strip().split(" ")
				if data[1:] in self.vars:
					data = self.vars[data[1:]]
				if data.startswith("!"):
					data = int(data[1:]) + 1
					#tmp = self.vars[data[2:]]
					#if tmp.startswith("192."):
					#	data = "10.0.0.1"
					#elif tmp.startswith("10."):
					#	data = "192.168.0.1"
					#data = self.vars[data[2:]]
				self.vars[var] = data

	
		return self.vars

#!/usr/bin/python
#Blake Hartstein
#2009-12-23
#Written for rule2alert
import re
import sys
from binascii import hexlify, unhexlify

class RevRegex:
	def __init__(self, rule):
		self.rule = rule

	def flatten(self):
		withpcre = 0
		failcase = 0
		out = ''
		pcres = re.findall('pcre:\s*"(.*?)";',self.rule)
		for pcre in pcres:
			#match = re.search('pcre:\s*"%s";' % pcre, self.rule)
			#out += 'flatten %s\r\n to \r\n' % pcre

			if not (pcre.startswith('/') or pcre.startswith('m/')):
				#print 'fail pcre format on %s' % pcre
				return None

			goodFormat = re.search('^m?\/(.*)\/[UGBmsiR]*$',pcre) #.*\\\/[a-zA-Z]*$',pcre)
			if not goodFormat:
				#print 'fail goodFormat on %s (from %s)' % (pcre,self.rule)
				return None

			tmp = goodFormat.group(1)

			#character replacements
			#this sux but need to replace ? characters, need to do this before unescaping them that way we don't replace legitimate '?' characters
			#tmp = re.sub('([^\\\\]).\\?','\\1',tmp)

			tmp = re.sub('\\\\x(([a-fA-F0-9]{2}\?)+)', '',tmp)
			tmp = re.sub('\\\\x(([a-fA-F0-9]{2})+)', '|\\1|',tmp)
			tmp = re.sub('\\\\n', '|0a|', tmp)
			tmp = re.sub('\\\\r', '|0d|', tmp)
			tmp = re.sub('\\\\d', '9', tmp)

			tmp = re.sub('\\\\([\\\/?])', '\\1', tmp)
			#tmp = re.sub('\\\\\\\\', '\\\\', tmp)
			tmp = re.sub('\\\\\\.', '.', tmp)
			tmp = re.sub('\\\\s[*+?]', ' ', tmp)

			#character classes
			#repeat operators (+,*,?,{})
			tmp = re.sub('\[.*?\](\?|\*)','',tmp)
			tmp = re.sub('\(.*?\)(\?|\*)','',tmp)
			tmp = re.sub('\((.*?)\)(\+)','\\1',tmp)
	
			tmp = re.sub('([^\\\\].)\+','\\1',tmp) #kill + for {1,}
			#\xff-ff ranges
			tmp = re.sub('\[([^\\\\]).*?\]','\\1',tmp)
			tmp = re.sub('(.){(\d+),?}', lambda mo: mo.group(1) * int(mo.group(2),0), tmp)
			#negated character classes

			#not handled yet

			#capture classes
			tmp = re.sub('\((.*?)\|.*?\)','\\1',tmp)
		
			#out += 'content:"%s";' % (tmp)
			out = 'content:"%s";' % tmp

			if out:
				#print "RULE FLAT"
				start = self.rule.find('pcre:')
				end = start + self.rule[start:].find('";') + 2
				self.rule = self.rule[:start] + out + self.rule[end:]

				#print self.rule

				out = ''

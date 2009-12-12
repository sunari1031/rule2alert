from Parser.RuleParser import Rule
import struct
from binascii import *
from ctypes import create_string_buffer

class PayloadGenrator:
    payload = None
    contents = []
    def __init__(self, rule_contents):
        self.contents = rule_contents
        
    def build(self):
        oldc = None
        itered = []
        for c in self.contents:
            if not oldc:
                c.ini = 0
                c.end = len(c.content)
            else:
                c.ini = oldc.end + 1
                c.end = c.ini + len(c.content)

            if c.offset and not oldc:
                c.ini = c.ini + offset
                c.end = c.end + offset

            if c.offset and oldc:
                # Here we should check for conflicts
                if c.ini < c.offset:
                    c.ini = offset
                    c.end = c.ini + len(c.content)

            if c.distance and oldc:
                if oldc.end + c.distance > c.ini:
                    c.ini = oldc.end + c.distance
                    c.end = oldc.end + c.distance + len(c.content)

            # Checks
            if c.depth and c.end > c.depth:
                print "Error here depth!" 

            # Checks
            if c.within and c.end > oldc.end + c.within:
                print "Error here within!" 
                
            oldc = c
            itered.append(c)
            print "-> Ini: " + str(c.ini) + " End: " + str(c.end)

        # perform padding
        self.payload = create_string_buffer(c.end)

        # write payloads
        for c in itered:
            if not c.negated:
                fmt = str(c.end - c.ini) + "s"
                flag=0
                tmp = ""
                i = 0
                while i < len(c.content):
                    if c.content[i]=="|" and (i>0 and c.content[i-1]!='\\' or i==0) and flag == 0:
                        flag = 1
                        i = i + 1
                        continue

                    if c.content[i]=="|" and i>0 and c.content[i-1]!='\\' and flag == 1:
                        print "unsetting"
                        flag = 0
                        i = i + 1
                        continue

                    if c.content[i]==" " and flag == 1:
                        i = i + 1
                        continue

                    if flag == 1:
                        tmp = tmp + "\\x%s" % c.content[i:i+2]
                        print "\\x" + c.content[i:i+2]
                        i = i + 1
                    else:
                        tmp = tmp + c.content[i]
                        
                    i = i + 1

                print "..."+tmp +" " + str(len(tmp))
                struct.pack_into(fmt, self.payload, c.ini, tmp)

        return self.payload
            
# We should deal here with the http modifiers (skiping by now)

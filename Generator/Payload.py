import struct
from binascii import *
from ctypes import create_string_buffer
import sys
import string

class PayloadGenerator:
    pkts = []
    payload = None
    contents = []
    itered = []

    def __init__(self, rule_contents):
        self.contents = rule_contents
        self.payload = None
        self.itered = []
        
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

        # buffer size
        max = 0
        for c in itered:
            if c.end > max:
                max = c.end

        # perform padding with ' 's (blank spaces)
        padding = ""
        for i in range(0,max):
            padding = padding + " "
        self.payload = create_string_buffer(max)
        struct.pack_into(str(max) + "s", self.payload, 0, padding)

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
                        flag = 0
                        i = i + 1
                        continue

                    if c.content[i]==" " and flag == 1:
                        i = i + 1
                        continue

                    if flag == 1:
                        tmp = tmp + a2b_hex(c.content[i:i+2])
                        i = i + 1
                    else:
                        tmp = tmp + c.content[i]
                        
                    i = i + 1

                struct.pack_into(fmt, self.payload, c.ini, tmp)

        self.itered = itered
        return self.payload

    def hexPrint(self):
        print "-------- Hex Payload Start ----------"
        for i in range(0,len(self.payload)):
            sys.stdout.write(" " + hexlify(self.payload[i]))
            if i > 0 and (i + 1) % 4 == 0:
                sys.stdout.write(" ")
            if i > 0 and (i + 1) % 8 == 0:
                print ""
        print "--------- Hex Payload End -----------"

    def asciiPrint(self):
        print "-------- Ascii Payload Start ----------"
        print self.payload.raw
        for i in range(0,len(self.payload)):
            c = self.payload.raw[i]
            if c in string.printable:
                sys.stdout.write(c)
            else:
                sys.stdout.write("\\x" + hexlify(c))
        print "\n--------- Ascii Payload End -----------"
            
    def PrintOffsets(self):
        print " Start        End"        
        if self.itered == []:
            return
        for c in self.itered:
            print "%05s  %10s" % (str(c.ini), str(c.end))
# We should deal with the http modifiers (skiping by now)
#

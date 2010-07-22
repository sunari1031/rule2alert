from scapy.all import *

"""
packets will always be as such
as long as it is TCP and established

packets[0] -> SYN
packets[1] -> SYN-ACK
packets[2] -> ACK
packets[3] -> DATA
packets[4] -> ACK
packets[5] -> FIN-ACK
packets[6] -> ACK
"""

class Evasion:
	def __init__(self, packets):
		self.type   = ""
		self.credit = ""
		self.packets = packets

	def fakeRst(self):
		self.credit = "Judy Novak"
		self.type   = "client"
		#Store the original ACK
		realAck = self.packets[2]
		
		#Increase the stored ACK's ACK #
		self.packets[2][TCP].ack += 1

		#Create the RST
		source      = self.packets[2][IP].dst
		destination = self.packets[2][IP].src
		srcport     = self.packets[2][TCP].dport
		dstport     = self.packets[2][TCP].sport
		seqnum      = self.packets[2][TCP].ack

		rst = IP(src=source, dst=destination)/TCP(sport=srcport, dport=dstport, flags="R", seq=seqnum)

		#The rst packet needs to go after packets[2]
		store = []
		for i in range(4):
			store.append(self.packets.pop())
		store.reverse()

		#Append the RST followed by the original ACK
		self.packets.append(rst)
		self.packets.append(realAck)

		for packet in store:
			self.packets.append(packet)

		return self.packets

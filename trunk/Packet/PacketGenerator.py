from scapy.all import *

class PacketGenerator:
	
	def __init__(self):
		self.proto = ""
		self.flow  = IP()
		self.sport = ""
		self.dport = ""
		self.src   = ""
		self.dst   = ""
		self.handshake = False
		self.packets = []


	def build(self):
		#If we need to call the handshake
		self.handshake = True
		hs = self.build_handshake()

		for p in hs:
			self.packets.append(p)

		if not self.handshake:
			client_isn = 1932
			server_isn = 1059


		return self.packets

	def build_handshake(self):
		client_isn = 1932
		server_isn = 1059

		syn = Ether()/IP(src=self.flow.src, dst=self.flow.dst)/TCP(flags="S", sport=self.proto.sport, dport=self.proto.dport, seq=client_isn)

		synack = Ether()/IP(src=self.flow.dst, dst=self.flow.src)/TCP(flags="SA", sport=self.proto.dport, dport=self.proto.sport, seq=server_isn, ack=syn.seq+1)
		
		ack = Ether()/IP(src=self.flow.src, dst=self.flow.dst)/TCP(flags="A", sport=self.proto.sport, dport=self.proto.dport, seq=syn.seq+1, ack=synack.seq+1)

		handshake = [syn,synack,ack]

		return handshake

	def get_seqack(self):
		if len(self.packets) == 0:
			return 0
		
		seq = self.packets[-1].seq
		ack = self.packets[-1].ack

		return seq,ack

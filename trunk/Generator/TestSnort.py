from subprocess import Popen, PIPE

class TestSnort:
	
	def __init__(self, snort_conf, pcap):
		self.alerts = ""
		self.cmd    = "snort -c %s -K none -q -A console -r %s" % (snort_conf, pcap)

	def run(self):
		p = Popen(self.cmd, shell=True, stdout=PIPE, stderr=PIPE)
		stdout, stderr = p.communicate()

		if stdout:
			return len(stdout)

		else:
			return 0

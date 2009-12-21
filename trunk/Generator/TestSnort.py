from subprocess import Popen, PIPE
import re

class SnortAlert:
    def __init__(self, gid, sid, rev, msg):
        #Trust only the sid...
        self.sid = sid
        self.gid = gid
        self.rev = rev
        self.msg = msg

    def __str__(self):
        return "[**] [%s:%s:%s] %s [**]" % (self.gid, self.sid, self.rev, self.msg)

class TestSnort:
    
    def __init__(self, snort_conf, pcap, logfile):
        self.logfile = logfile
        self.alerts = []
        self.cmd    = "snort -c %s -K none -q -A console -r %s" % (snort_conf, pcap)

    def run(self):
        p = Popen(self.cmd, shell=True, stdout=PIPE, stderr=PIPE)
        stdout, stderr = p.communicate()

		stdout = stdout.splitlines()

        if stdout:
            return len(stdout)

        else:
            return 0

    def readSnortAlerts(self):
        #12/21-16:14:50.971883  [**] [1:20000000:1] Snort alert [**] [Priority: 0] {TCP} 192.168.0.1:9001 -> 1.1.1.1:80
        #                            [gid:sid:rev]
        p = re.compile(r'\[\*\*\]\s+\[(?P<gid>\d+):(?P<sid>\d+):(?P<rev>\d+)\]\s*(?P<msg>.*)\s*\[\*\*\]')
        f = open(self.logfile, "r")
        for line in f.read().splitlines():
            m = p.search(line)
            if m:
                try:
                    self.alerts.append(SnortAlert(m.group("gid"),m.group("sid"),m.group("rev"),m.group("msg")))
                except:
                    print "Error parsing alert from " + str(line)

    def printAlerts(self):
        for alert in self.alerts:
            print alert

'''
t = TestSnort("asdf","asdf","/var/log/snort/alert.1")
t.readSnortAlerts()
t.printAlerts()
'''

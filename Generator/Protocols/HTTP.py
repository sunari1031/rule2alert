
class HTTP:
	
	def __init__(self):
		self.method     = ""
		self.uri        = "/"
		self.version    = "HTTP/1.1"
		self.host       = "www.malforge.com"
		self.user_agent = "Mozilla/5.0 (Windows; U; Windows NT 6.1; en-US; rv:1.9.1.5) Gecko/20091102 Firefox/3.5.5 (.NET CLR 3.5.30729)"
		self.keep_alive = "300"
		self.connection = "keep-alive"

	def build(self):
		payload = "%s %s %s\r\nHost: %s\r\nUser-Agent: %s\r\nKeep-Alive: %s\r\nConnection: %s\r\n\r\n" % (self.method, self.uri, self.version, self.host, self.user_agent, self.keep_alive, self.connection)
	
		return payload

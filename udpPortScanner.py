from logging import getLogger, ERROR
getLogger("scapy.runtime").setLevel(ERROR)
from scapy.all import *
import sys


rtr_ipaddr = "10.10.111.1" # IP addr of router
min_port = 0
max_port = 100

ports = range(int(min_port), int(max_port) + 1)

openportlist = []
closedportlist = []



def checkrtrup(ip):
	conf.verb = 0
	try:
		ping = sr1(IP(dst = ip)/ ICMP())
		print "Host is up. Scanning..."
	except Exception:
		print "Error in resolving router"
		sys.exit(1)

def scanport(port):
	conf.verb = 0
	srcport = RandShort()
	pkt_udp = sr1(IP(dst = rtr_ipaddr)/UDP(sport = srcport, dport = port), inter=0.5, retry=5, timeout=5)
	

	if pkt_udp is None:
		ans,unans = sr(IP(dst = rtr_ipaddr)/UDP(sport = srcport, dport = port), inter=0.5, retry=5, timeout=5)
	
		unans.summary()

	return pkt_udp

print "UDP Port Scanning of ip " + str(rtr_ipaddr) + " is started"

checkrtrup(rtr_ipaddr)


for port in ports:

	status = scanport(port)

	if status is None:
		openportlist.append(port)
	else:
		closedportlist.append(port)

print "OPEN: " + str(openportlist)
print "CLOSED: "+ str(closedportlist)

print "UDP Port Scanning of ip " + str(rtr_ipaddr) + " is finished"

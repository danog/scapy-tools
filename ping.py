from scapy.all import *
import os

if len(sys.argv) < 2:
        print("Usage: ping.py host")
        sys.exit()

ping = sr(IP(dst=os.sys.argv[1])/ICMP(), timeout=5)
if ping and len(ping[0].res):
    if ping[0].res[0][1].payload.code == 0:
        print("echo reply from "+ping[0].res[0][1].src+": icmp_seq "+str(ping[0].res[0][1].payload.seq)+", ttl "+str(ping[0].res[0][1].ttl))
    else:
        print("Got another ICMP code ("+str(ping[0].res[0][1].payload.code)+") from "+ping[0].res[0][1].src)
else:
    print("Failure")

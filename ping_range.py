from scapy.all import *
import os


for x in range(0, 255):
    ping = sr(IP(dst="192.168.1."+str(x))/ICMP(), timeout=1, verbose=False)
    if ping and len(ping[0].res):
        if ping[0].res[0][1].payload.code == 0:
            print("echo reply from "+ping[0].res[0][1].src+": icmp_seq "+str(ping[0].res[0][1].payload.seq)+", ttl "+str(ping[0].res[0][1].ttl))
        else:
            print("Got another ICMP code ("+str(ping[0].res[0][1].payload.code)+") from "+ping[0].res[0][1].src)
    else:
        print("FAILURE for 192.168.1."+str(x))
from scapy.all import *
import os

if len(sys.argv) < 2:
        print("Usage: traceroute.py host")
        sys.exit()

lastsrc = -1
for ttl in range(0, 255):
    ans, unans = sr(IP(dst=os.sys.argv[1], ttl=ttl)/ICMP(), timeout=5, verbose = False)
    if ans:
        #if (ans.res[0][1].src == lastsrc): quit()
        if ans.res[0][1].payload.code == 0:
            print("TTL = "+str(ttl)+"; echo reply from "+ans.res[0][1].src+": icmp_seq "+str(ans.res[0][1].payload.seq)+", ttl "+str(ans.res[0][1].ttl))
        else:
            print("TTL = "+str(ttl)+"; Got another ICMP code ("+str(ans.res[0][1].payload.code)+") from "+ans.res[0][1].src)
        #lastsrc = ans.res[0][1].src
    else:
        print("TTL = "+str(ttl)+"; Failure")

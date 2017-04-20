from scapy.all import *
import os
if len(sys.argv) < 3:
        print("Usage: nmap.py UDP host")
        print("Usage: namp.py TCP flags host")
        sys.exit()

for port in range(1, 65536):
    if sys.argv[1] == "UDP":
        packet = IP(dst=os.sys.argv[2])/UDP(dport=port)


    elif sys.argv[1] == "TCP":
        if len(sys.argv) < 4:
                print("Usage: nmap.py TCP flags host")
                sys.exit()
        packet = IP(dst=os.sys.argv[3])/TCP(dport=port, flags=sys.argv[2])
    else:
        raise ValueError("Invalid scan type provided!")

    ans, unans=sr(packet, verbose = False, timeout=0.1)
    if ans:
        print("Port "+str(port)+": open")
    else:
        print("Port "+str(port)+": closed")

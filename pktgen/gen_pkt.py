from scapy.all import *
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.inet6 import IPv6
import string

import random
import pprint

import sys
sys.path.insert(1,'/home/croid/exp_config')
from exp_config import HISTORYTRAFFIC,ONE_PKT_SIZE,PKT_FILE_MAP,topo_G

import numpy as np

hostid=1

def payload_gen(length):    
    chars=string.ascii_letters
    payload=''.join(random.choice(chars) for i in range(length))
    return payload

def host_traffic_gen(hostid):
    isd_dict={s:{d:[] for d in range(len(topo_G.nodes()))} for s in range(len(topo_G.nodes()))}
    for slicenum,slicedict in enumerate(HISTORYTRAFFIC):
        for k,v in slicedict.items():
            if v ==0:
                continue
            random.seed(3)
            if random.randint(0,1)==1:
                srcid=k[0]        
                dstid=k[1]
            else:
                srcid=k[1]        
                dstid=k[0]
            if srcid == hostid:
                length=int(ONE_PKT_SIZE[PKT_FILE_MAP[slicenum]])
                while length > 0 :
                    pkt = IP(src='10.0.0.'+str(srcid), dst='10.0.0.'+str(dstid))/UDP(sport=slicenum,dport=slicenum)        
                    if length > 1500:
                        payload = 1500-len(pkt)
                    else:
                        payload = length
                    data = payload_gen(payload)
                    length = length-1500
                    pkt = pkt/data
                    isd_dict[srcid][dstid].append(pkt)

        
        print(f"gen_pkt {str(hostid).zfill(2)}: sir yes sir!!!")
        return isd_dict

"""
dir_name = "pktgen_random"
if not os.path.exists(dir_name):
    os.makedirs(dir_name)

for s in range(len(topo_G.nodes())):
    file_name="randomgen"+str(s)+".pcap"
    pcappath="./"+dir_name+"/"+file_name
    wrpcap(pcappath,pkt_dict[s])
"""


from scapy.all import *
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.inet6 import IPv6
import string

import os
import inspect
import time
from collections import Counter
from pathlib import Path
import pprint

from multiprocessing import Pool

import sys
sys.path.insert(1,'./')
from exp_config.exp_config import \
PKT_FILE_MAP, NUM_PKT, \
SCHEDULER_TYPE, EXP_TYPE, RANDOM_SEED_NUM, \
GOGO_TIME, TOTAL_TIME, FIRST_TIME_SLEEP, \
ONE_PKT_SIZE, INNTER_ARRIVAL_TIME,\
topo_G, \
topo_SLICENUM, topo_GNode0_alignto_mininetSwitchNum, \
HISTORYTRAFFIC


###
start = (1*(len('server')))
end = (-1*len('.py'))
hostid = os.path.basename(inspect.getfile(inspect.currentframe()))
hostid = int(hostid[start:end])

random.seed(RANDOM_SEED_NUM)

def G_to_M(GNode):
    return GNode + topo_GNode0_alignto_mininetSwitchNum

def M_to_G(SwitchNum):
    return SwitchNum - topo_GNode0_alignto_mininetSwitchNum

def host_traffic_gen(hostid):
    def payload_gen(length):    
        chars=string.ascii_letters
        payload=''.join(random.choice(chars) for i in range(length))
        return payload
        
    isd_dict={i:{(s,d):[] \
              for d in range(G_to_M(len(topo_G.nodes()))) for s in range(G_to_M(len(topo_G.nodes())))}\
              for i in range(topo_SLICENUM)}

    for i,slicedict in HISTORYTRAFFIC.items():
        for k,v in slicedict.items():
            if v == 0:
                continue

            if random.randint(0,1)==1:
                srcid=G_to_M(k[0])
                dstid=G_to_M(k[1])
            else:
                srcid=G_to_M(k[1])       
                dstid=G_to_M(k[0])

            if srcid == hostid:
                length=int(ONE_PKT_SIZE[PKT_FILE_MAP[i]])
                while length > 0 :
                    pkt = IP(src='10.0.0.'+str(srcid), dst='10.0.0.'+str(dstid))/UDP(sport=i,dport=1)        
                    if length > 1500:
                        payload = 1500-len(pkt)
                    else:
                        payload = length
                    data = payload_gen(payload)
                    length = length-1500
                    pkt = pkt/data
                    isd_dict[i][(srcid,dstid)].append(pkt)
        
    return isd_dict


###
flow = [[]]
print(f"server {str(hostid)}: ready")


class Counter(dict):
    def __missing__(self, key):
        return 0


def send_flow(i,srcid,dstid):
    time.sleep(FIRST_TIME_SLEEP*i)
    sendp(flow[i][(srcid,dstid)], inter=INNTER_ARRIVAL_TIME[i], count=NUM_PKT[i], verbose=False)

def sniff_flow(hostid):
    interface_port = 'h'+str(hostid)+'-eth0'
    sniff(iface=interface_port, prn=lambda pkt: "%s,%s" % (pkt.sniffed_on, pkt.summary()) )
       


def main():
    sniff_flow(hostid)


if __name__ == '__main__':
    timestamp = float(time.time())
    time.sleep(GOGO_TIME-timestamp-10)
    while (timestamp := float(time.time())) < GOGO_TIME:
        pass
    main()
from scapy.all import *
from scapy.layers.inet import Ether, IP, UDP, TCP
from scapy.layers.inet6 import IPv6
import string

import os
import inspect
import time
from collections import Counter
from pathlib import Path
import pprint

from multiprocessing import Pool,Process,cpu_count
from subprocess import Popen

import sys
sys.path.insert(1,"./")
from exp_config.exp_config import \
SLICE_TRAFFIC_MAP, NUM_PKT,     \
SCHEDULER_TYPE, EXP_TYPE, RANDOM_SEED_NUM,     \
GOGO_TIME, TOTAL_TIME, FIRST_TIME_SLEEP,     \
ONE_PKT_SIZE, INNTER_ARRIVAL_TIME,     \
topo_G,     \
topo_SLICENDICT,     \
HISTORYTRAFFIC

from exp_utils.exp_utils import \
G_to_M, num_to_hostmac,num_to_hostipv4,clienttraffictype_to_L4port

time_ctrl=False

###
start = (1*(len("client")))
end = (-1*len(".py"))
hostid = os.path.basename(inspect.getfile(inspect.currentframe()))
hostid = int(hostid[start:end])

random.seed(RANDOM_SEED_NUM)
runcnt = 0

class Counter(dict):
    def __missing__(key):
        return 0

def host_traffic_gen(hostid):
    gen_ctrl = False

    def payload_gen(length):
        chars=string.ascii_letters
        payload="".join(random.choice(chars) for i in range(length))
        return payload

    isd_dict={i:{(G_to_M(s),G_to_M(d)):[] \
              for d in topo_G.nodes() for s in topo_G.nodes()}\
              for i in topo_SLICENDICT.keys()}

    for i,slicedict in HISTORYTRAFFIC.items():
        for k,v in slicedict.items():
            if v == 0:
                continue

            srcid=G_to_M(k[0])
            dstid=G_to_M(k[1])

            if srcid == hostid:
                gen_ctrl = True
                length=int(ONE_PKT_SIZE[i])
                L4sport=int(clienttraffictype_to_L4port(SLICE_TRAFFIC_MAP[i],hostid))+int(srcid)*10+int(dstid)
                while length > 0 :
                    pkt = Ether(src=num_to_hostmac(srcid), dst=num_to_hostmac(dstid))/   \
                          IP(src=num_to_hostipv4(srcid), dst=num_to_hostipv4(dstid))/    \
                          UDP(sport=L4sport,dport=L4sport)
                    if length > 1500:
                        payload = 1500                        
                    else:
                        payload = length
                    length = length - 1500    
                    data = payload_gen(payload)                    
                    pkt = pkt/data
                    isd_dict[i][(srcid,dstid)].append(pkt)

    if gen_ctrl == False:
        return None
    else:
        return isd_dict


flow = host_traffic_gen(hostid)




def send_flow(i,srcid,dstid):
    timestamp=time.time()
    myinterface="h"+str(hostid)+"-eth0"
    myL2socket = conf.L2socket(iface=myinterface)
    if INNTER_ARRIVAL_TIME[i] > 0.01:
        sendp(flow[i][(srcid,dstid)],inter=INNTER_ARRIVAL_TIME[i],count=NUM_PKT[i],iface=myinterface,verbose=False,socket=myL2socket)
    else:
        sendp(flow[i][(srcid,dstid)],inter=INNTER_ARRIVAL_TIME[i],count=NUM_PKT[i],iface=myinterface,verbose=False,socket=myL2socket)
    print(f"client {str(srcid)}-{str(dstid)} type{i}:done \t{(timestamp-GOGO_TIME):.6f}\t{(time.time()-timestamp):.6f} s")

    """
    ###sendp(flow[i][(srcid,dstid)],count=10,iface=myinterface,verbose=False,socket=myL2socket)
    ###send(flow[i][(srcid,dstid)],count=10,iface=myinterface,verbose=False,socket=myL3socket)
    ###sendpfast(flow[i][(srcid,dstid)],loop=10,iface=myinterface,file_cache=True)
    """

def pre_send_flow(i,srcid,dstid):
    myinterface="h"+str(hostid)+"-eth0"
    myL2socket = conf.L2socket(iface=myinterface)
    sendp(flow[i][(srcid,dstid)],count=len(flow[i][(srcid,dstid)]),iface=myinterface,verbose=False,socket=myL2socket)

def sniff_flow(hostid):
    interface_port = "h"+str(hostid)+"-eth0"
    sniff(iface=interface_port,prn=lambda pkt:pkt.summary())


def cnt_flow():
    processlist=[]
    with Pool(processes=cpu_count()) as pool:
        for i,slicedict in flow.items():
            for e,v in slicedict.items():
                srcid=e[0]
                dstid=e[1]
                if len(v) != 0:
                    print(f"client {str(srcid)}-{str(dstid)} type{i} \t{(time.time()-GOGO_TIME):.6f}\t async")
                    processlist.append(pool.apply_async(send_flow,(i,srcid,dstid)))
        pool.close()
        pool.join()

def pre_cnt_flow():
    processlist=[]
    with Pool(processes=cpu_count()) as prepool:
        for i,slicedict in flow.items():
            for e,v in slicedict.items():
                srcid=e[0]
                dstid=e[1]
                if len(v) != 0:
                    processlist.append(prepool.apply_async(pre_send_flow,(i,srcid,dstid)))
        prepool.close()
        prepool.join()


def main():
    if flow == None:
        print(f"client {str(hostid)}:nothing to send")
    else:
        print(f"client {str(hostid)}:start")        
        cnt_flow()

def pre_main():
    if flow == None:
        print(f"client {str(hostid)}:nothing to send")
    else:
        timestamp=time.time()
        print(f"client {str(hostid)}:prestart")
        pre_cnt_flow()
        print(f"client {str(hostid)}:predone {(time.time()-timestamp):.6f} s")

if __name__ == "__main__":
    if GOGO_TIME:
        pre_main()
        time.sleep(GOGO_TIME-float(time.time())-60)
    else:
        pre_main()
        time.sleep(60)
    while (timestamp := float(time.time())) < GOGO_TIME:
        pass
    main()
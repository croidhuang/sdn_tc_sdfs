from tabnanny import verbose
from scapy.all import *
from scapy.layers.inet import Ether, IP, UDP, TCP
from scapy.layers.inet6 import IPv6
import string

import os
import inspect
import time
from pathlib import Path
import pprint
import copy


from pebble import ProcessPool
from multiprocessing import Pool,cpu_count,TimeoutError

import sys
sys.path.insert(1,"./")
from exp_config.exp_config import \
SLICE_TRAFFIC_MAP, NUM_PKT,     \
SCHEDULER_TYPE, EXP_TYPE, RANDOM_SEED_NUM,     \
GOGO_TIME, TOTAL_TIME, READPKT_TIME, BETWEEN_HISTORY_EXTRA_TIME,     \
ONE_PKT_SIZE, INNTER_ARRIVAL_TIME,     \
topo_G,     \
topo_SLICENDICT,     \
HISTORYTRAFFIC,EXTRATRAFFIC

from exp_utils.exp_utils import \
G_to_M, M_to_G ,num_to_hostmac,num_to_hostipv4,clienttraffictype_to_L4port



###辨別server
start = (1*(len("client")))
end = (-1*len(".py"))
hostid = os.path.basename(inspect.getfile(inspect.currentframe()))
hostid = int(hostid[start:end])

random.seed(RANDOM_SEED_NUM)



#生成flow
def host_traffic_gen(hostid, dict_ctrl):
    gen_ctrl = False

    def payload_gen(length):
        chars = string.ascii_letters
        payload = "".join(random.choice(chars) for i in range(length))
        return payload

    hostlist = []
    for s in topo_G.nodes():
        try:
            if topo_G.nodes[s]['host'] != []:
                for h in topo_G.nodes[s]['host']:
                    hostlist.append(h)
        except:
            pass

    isd_dict = {i:{(G_to_M(s),G_to_M(d)):[] \
              for d in hostlist for s in hostlist}\
              for i in topo_SLICENDICT.keys()}

    if dict_ctrl == "history" or dict_ctrl == "both":
        for i,slicedict in HISTORYTRAFFIC.items():
            for k,v in slicedict.items():
                if v == 0:
                    continue

                srcid = G_to_M(k[0])
                dstid = G_to_M(k[1])

                if srcid == hostid:
                    gen_ctrl = True
                    length = int(v*float(INNTER_ARRIVAL_TIME[i]/1))
                    L4sport = int(clienttraffictype_to_L4port(i,hostid))+int(dstid)
                    while length > 0 :
                        pkt = Ether(src = num_to_hostmac(srcid), dst = num_to_hostmac(dstid))/   \
                            IP(src = num_to_hostipv4(srcid), dst = num_to_hostipv4(dstid))/    \
                            UDP(sport = L4sport,dport = L4sport)

                        if length > int(1500*1.5):
                            payload = (1500-len(pkt))
                            length = length - 1500
                            #per1500
                            data = payload_gen(payload)
                            pkt = pkt/data
                            isd_dict[i][(srcid,dstid)].append(pkt)

                        elif length > len(pkt):
                            payload = int((length-len(pkt)*2)/2)

                            #splite 750*2
                            data1 = payload_gen(payload)
                            data2 = payload_gen(payload)
                            pkt1 = pkt/data1
                            pkt2 = pkt/data2
                            isd_dict[i][(srcid,dstid)].append(pkt1)
                            isd_dict[i][(srcid,dstid)].append(pkt2)
                            length = -1
                        else:
                            #header only
                            isd_dict[i][(srcid,dstid)].append(pkt)
                            length = length - 1500



    if dict_ctrl == "extra" or dict_ctrl == "both":
        for i,slicedict in EXTRATRAFFIC.items():
            for k,v in slicedict.items():
                if v == 0:
                    continue

                srcid = G_to_M(k[0])
                dstid = G_to_M(k[1])

                if srcid == hostid:
                    gen_ctrl = True
                    length = int(v*float(INNTER_ARRIVAL_TIME[i]/1))
                    L4sport = int(clienttraffictype_to_L4port(i,hostid))+int(dstid)
                    while length > 0 :
                        pkt = Ether(src = num_to_hostmac(srcid), dst = num_to_hostmac(dstid))/   \
                            IP(src = num_to_hostipv4(srcid), dst = num_to_hostipv4(dstid))/    \
                            UDP(sport = L4sport,dport = L4sport)

                        if length > int(1500*1.5):
                            payload = (1500-len(pkt))
                            length = length - 1500
                            #per1500
                            data = payload_gen(payload)
                            pkt = pkt/data
                            isd_dict[i][(srcid,dstid)].append(pkt)

                        elif length > len(pkt):
                            payload = int((length-len(pkt)*2)/2)

                            #splite 750*2
                            data1 = payload_gen(payload)
                            data2 = payload_gen(payload)
                            pkt1 = pkt/data1
                            pkt2 = pkt/data2
                            isd_dict[i][(srcid,dstid)].append(pkt1)
                            isd_dict[i][(srcid,dstid)].append(pkt2)
                            length = -1
                        else:
                            #header only
                            isd_dict[i][(srcid,dstid)].append(pkt)
                            length = length - 1500

    if gen_ctrl == False:
        return None
    else:
        return isd_dict

# 三種flow
history_flow = host_traffic_gen(hostid,"history")
extra_flow = host_traffic_gen(hostid,"extra")
flow = host_traffic_gen(hostid,"both")

# sniff備用
def sniff_flow(hostid):
    interface_port = "h"+str(hostid)+"-eth0"
    sniff(iface = interface_port,prn = lambda pkt:pkt.summary())


#發送flow
"""
###sendp(flow[i][(srcid,dstid)],count = 10,iface = myinterface,verbose = False,socket = myL2socket)
###send(flow[i][(srcid,dstid)],count = 10,iface = myinterface,verbose = False,socket = myL3socket)
###sendpfast(flow[i][(srcid,dstid)],loop = 10,iface = myinterface,file_cache = True)
"""
def send_flow(i,srcid,dstid,timestamp):
    
    strpkt=''
    for pkt in flow[i][(srcid,dstid)]:
        strpkt=strpkt+str(len(pkt))+'_'
    print(f"client {str(hostid)}:start\t{strpkt}")
    myinterface = "h"+str(hostid)+"-eth0"
    myL2socket = conf.L2socket(iface = myinterface)
    while (timestamp := time.time()) < GOGO_TIME:
        pass
    sendp(flow[i][(srcid,dstid)],inter = INNTER_ARRIVAL_TIME[i],count = NUM_PKT[i],iface = myinterface,verbose = False, socket = myL2socket,realtime=False,return_packets=False)

def pre_send_history_flow(i,srcid,dstid,timestamp):
    print(f"client {str(hostid)}:prehistorystart")
    myinterface = "h"+str(hostid)+"-eth0"
    myL2socket = conf.L2socket(iface = myinterface)
    sendp(history_flow[i][(srcid,dstid)],count = 1,iface = myinterface,verbose = False,socket = myL2socket)
    print(str("client"+ str(hostid)+":prehistorydone "+str(time.time()-timestamp)+ "s"))

def pre_send_extra_flow(i,srcid,dstid,timestamp):
    print(f"client {str(hostid)}:preextrastart")
    myinterface = "h"+str(hostid)+"-eth0"
    myL2socket = conf.L2socket(iface = myinterface)
    sendp(extra_flow[i][(srcid,dstid)],count = 1,iface = myinterface,verbose = False,socket = myL2socket)
    print(str("client"+ str(hostid)+":preextradone "+str(time.time()-timestamp)+ "s"))


#multithread開生成中有生成的flow
def pre_history_flow(timestamp):
    with ProcessPool() as pre_history_pool:
        for i,slicedict in history_flow.items():
            for e,v in slicedict.items():
                srcid = e[0]
                dstid = e[1]
                if len(v) != 0:
                    timeout = 10
                    pre_history_pool.schedule(pre_send_history_flow, (i,srcid,dstid,timestamp), timeout = timeout)
        pre_history_pool.close()
        pre_history_pool.join()

def pre_extra_flow(timestamp):
    with ProcessPool() as pre_extra_pool:
        for i,slicedict in extra_flow.items():
            for e,v in slicedict.items():
                srcid = e[0]
                dstid = e[1]
                if len(v) != 0:
                    timeout = 10
                    pre_extra_pool.schedule(pre_send_extra_flow, (i,srcid,dstid,timestamp), timeout = timeout)
        pre_extra_pool.close()
        pre_extra_pool.join()

def cnt_flow(timestamp):
    with ProcessPool() as pool:
        for i,slicedict in flow.items():
            for e,v in slicedict.items():
                srcid = e[0]
                dstid = e[1]
                if len(v) != 0:
                    timeout = TOTAL_TIME
                    pool.schedule(send_flow, (i,srcid,dstid,timestamp), timeout = timeout)
        pool.close()
        pool.join()
"""
# 原生pool寫法留存後來改用pebble套件幫忙管理timeout強制關閉
def cnt_flow():
    processlist=[]
    with Pool(processes=cpu_count()) as pool:
        for i,slicedict in flow.items():
            for e,v in slicedict.items():
                srcid=e[0]
                dstid=e[1]
                if len(v) != 0:
                    processlist.append(pool.apply_async(send_flow,(i,srcid,dstid)))
        pool.close()
        pool.join()
"""

#整個flow沒有的話不執行
def main(GOGO_TIME):
    timestamp = GOGO_TIME
    if flow == None:
        print(f"client {str(hostid)}:nothing to send")
    else:
        cnt_flow(timestamp)

def pre_main():
    timestamp = time.time()
    if history_flow == None:
        print(f"client {str(hostid)}:nothing to presend")
    else:
        pre_history_flow(timestamp)
    time.sleep(BETWEEN_HISTORY_EXTRA_TIME)
    if extra_flow == None:
        print(f"client {str(hostid)}:nothing to extrasend")
    else:
        pre_extra_flow(timestamp)


# 主要執行
if __name__ == "__main__":
    pre_main()
    sleeptime = (GOGO_TIME-time.time()-READPKT_TIME)
    if sleeptime > 2:
        time.sleep(sleeptime)
    main(GOGO_TIME)
from scapy.all import *
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.inet6 import IPv6

import os
import inspect
import time
from collections import Counter
from pathlib import Path

import sys
sys.path.insert(1,"./")
from exp_config.exp_config import    \
SLICE_TRAFFIC_MAP, PKT_FILE_LIST, CSV_OUTPUTPATH, NUM_PKT,    \
SCHEDULER_TYPE, EXP_TYPE, RANDOM_SEED_NUM,    \
GOGO_TIME, TOTAL_TIME, FIRST_TIME_SLEEP,    \
ONE_PKT_SIZE, INNTER_ARRIVAL_TIME,     \
topo_G,    \
topo_SLICENDICT,topo_GNode0_alignto_mininetSwitchNum,     \
HISTORYTRAFFIC

from exp_utils.exp_utils import \
G_to_M, num_to_hostmac, num_to_hostipv4


import numpy as np

start = (1*(len("server")))
end = (-1*len(".py"))
hostid = os.path.basename(inspect.getfile(inspect.currentframe()))
hostid = int(hostid[start:end])


def hostid_to_slice(hostid):
    slice = hostid-8
    return slice


def slice_to_server(slice):
    hostid = slice+8
    return hostid


def slice_to_client(slice):
    hostid = slice+1
    return hostid


flow = {k:0 for k in topo_SLICENDICT}
timerecord = {k:0 for k in topo_SLICENDICT}
i = hostid_to_slice(hostid)
p = str(Path(PKT_FILE_LIST.get(SLICE_TRAFFIC_MAP[i])))
flow[i] = rdpcap(p)
timerecord[i] = [0]*len(flow[i])
print(f"server {str(hostid)}: ready")


class Counter(dict):
    def __missing__(self, key):
        return 0


L3_ctrl = 0
L4_ctrl = 0

pkt_ctrl = {}
for i in topo_SLICENDICT:
    pkt_ctrl[i] = Counter()


def pc_flow(pkt, i):
    L3_ctrl = 1
    L4_ctrl = 1

    while L3_ctrl == 1:
        try:
            src_ip = pkt[IP].src
            dst_ip = pkt[IP].dst

            L3_ctrl = 0
            break
        except:
            src_ip = "0.0.0.0"
            dst_ip = "0.0.0.0"
        try:
            src_ip = pkt[IPv6].src
            dst_ip = pkt[IPv6].dst

            L3_ctrl = 0
            break
        except:
            src_ip = "0:0:0:0:0:0:0:0"
            dst_ip = "0:0:0:0:0:0:0:0"
        break

    while L4_ctrl == 1:
        try:
            src_port = pkt[TCP].sport
            dst_port = pkt[TCP].dport
            L4_ctrl = 0
            break
        except:
            src_port = 0
            dst_port = 0
        try:
            src_port = pkt[UDP].sport
            dst_port = pkt[UDP].dport
            L4_ctrl = 0
            break
        except:
            src_port = 0
            dst_port = 0
        break

    src_socket=str(src_ip)+":"+str(src_port)+"-"+str(dst_ip)+":"+str(dst_port)
    dst_socket=str(dst_ip)+":"+str(dst_port)+"-"+str(src_ip)+":"+str(src_port)    
    chk_socket=num_to_hostipv4(slice_to_client(i))+":"+str(src_port)+"-"+num_to_hostipv4(slice_to_server(i))+":"+str(dst_port)

  
    if pkt_ctrl[i][src_socket] == 0 and pkt_ctrl[i][dst_socket] == 0:
        pkt_ctrl[i][src_socket] = 1
        pkt_ctrl[i][dst_socket] = 0
    return src_socket, chk_socket


def sendp_flow(i, sendp_count):
    timer = time.time()
    timewait = INNTER_ARRIVAL_TIME[i]

    j = sendp_count
    pkt = flow[i][j]
    pkt_socket, chk_socket = pc_flow(pkt, i)
    if pkt_ctrl[i][pkt_socket] == 0:
        try:
            flow[i][j][IP].src = num_to_hostipv4(slice_to_server(i))
            flow[i][j][IP].dst = num_to_hostipv4(slice_to_client(i))
            print(f"send={pkt_socket}")
            sendp(flow[i][j], verbose=False)
        except:
            print("pass")
            pass

        timerecord[i][j] = (time.time())
        sendp_count += 1

        timewait = timewait-(time.time()-timer)
        if timewait > 0:
            time.sleep(timewait)
    elif pkt_ctrl[i][pkt_socket] == 1:
        print(f"wait={pkt_socket}")
        timewait = sniff_flow(i, chk_socket, timer, timewait)
        timerecord[i][j] = (time.time())
        sendp_count += 1

        if timewait > 0:
            time.sleep(timewait)
    return sendp_count


def sniff_flow(i, wait_socket, timer, timewait):
    t = "h"+str(slice_to_server(i))+"-eth0"
    while timewait > 0:
        try:
            pkt = sniff(iface=t, count=1, timeout=timewait)
            pkt_socket, chk_socket = pc_flow(pkt[0], i)
        except:
            timewait = timewait-(time.time()-timer)
            continue
        if pkt_socket == wait_socket:
            print(f"{pkt_socket}=={wait_socket}")
            break
        else:
            print(f"{pkt_socket}!={wait_socket}")
            timewait = timewait-(time.time()-timer)
            continue
    return timewait


def cnt_flow(i):
    sendp_count = 0
    time.sleep(FIRST_TIME_SLEEP*i)
    while sendp_count < NUM_PKT[i]:
        sendp_count = sendp_flow(i, sendp_count)

    timerecord[i] = np.array(timerecord[i])
    csv_name = CSV_OUTPUTPATH+str(i)+"_server.csv"
    np.savetxt(csv_name, timerecord[i], fmt="%lf", delimiter=",")


def main():
    cnt_flow(hostid_to_slice(hostid))


if __name__ == "__main__":
    if GOGO_TIME:
        timestamp = float(time.time())
        time.sleep(GOGO_TIME-timestamp-10)
    while (timestamp := float(time.time())) < GOGO_TIME:
        pass
    main()

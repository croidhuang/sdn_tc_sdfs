from socket import timeout
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
import socket

from pebble import ProcessPool
from multiprocessing import Pool, cpu_count, TimeoutError

from subprocess import Popen

import sys
sys.path.insert(1, "./")
from exp_config.exp_config import \
SLICE_TRAFFIC_MAP, NUM_PKT,     \
SCHEDULER_TYPE, EXP_TYPE, RANDOM_SEED_NUM,     \
GOGO_TIME, TOTAL_TIME, READPKT_TIME, BETWEEN_HISTORY_EXTRA_TIME,     \
ONE_PKT_SIZE, INNTER_ARRIVAL_TIME,     \
topo_G,     \
topo_SLICENDICT,     \
HISTORYTRAFFIC, EXTRATRAFFIC

from exp_utils.exp_utils import \
G_to_M, M_to_G , num_to_hostmac, num_to_hostipv4, clienttraffictype_to_L4port



###辨別server
start = (1*(len("client")))
end = (-1*len(".py"))
hostid = os.path.basename(inspect.getfile(inspect.currentframe()))
hostid = int(hostid[start:end])

random.seed(RANDOM_SEED_NUM)

L4sport_list=[i for i in range(1025,65536)]

#生成flow
def host_traffic_gen(hostid, dict_ctrl):
    def payload_gen(per_pkt_length):
        chars = string.ascii_letters
        payload = "".join(random.choice(chars) for i in range(per_pkt_length))
        return payload

    def trafficlist_gen(TRAFFIC, isd_dict, listenport_dict, gen_ctrl):
        for i, slicedict in TRAFFIC.items():
            for k, v in slicedict.items():
                if v == 0:
                    continue
                else:
                    flow_user_total = int(v/(ONE_PKT_SIZE[i]/INNTER_ARRIVAL_TIME[i]))+1

                srcid = G_to_M(k[0])
                dstid = G_to_M(k[1])

                if dstid == hostid:
                    gen_ctrl = True
                    L4dport = clienttraffictype_to_L4port(i, hostid, dstid)
                    """
                    scapy
                    """
                    """
                    #server
                    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                    s.bind((num_to_hostipv4(dstid), L4dport))
                    """

                    listenport_dict[(str(L4dport))] = 1

                if srcid == hostid:
                    gen_ctrl = True
                    for user_num in range(flow_user_total):
                        isd_dict[i][(srcid, dstid)].append([])
                        pkt_length = int(float(v/flow_user_total)*float(INNTER_ARRIVAL_TIME[i]/1))
                        L4sport = random.choice(L4sport_list)
                        L4sport_list.remove(L4sport)
                        L4dport = clienttraffictype_to_L4port(i, hostid, dstid)

                        """
                        scapy
                        """
                        """
                        #client
                        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                        s.connect((num_to_hostipv4(dstid), L4dport))
                        """                        

                        pkt = Ether(src = num_to_hostmac(srcid), dst = num_to_hostmac(dstid))/   \
                        IP(src = num_to_hostipv4(srcid), dst = num_to_hostipv4(dstid))/    \
                        UDP(sport = L4sport, dport = L4dport)

                        pkt_total = int(pkt_length/1500)+1
                        per_pkt_length = int(pkt_length / pkt_total)
                        for pi in range(pkt_total):
                            payload = payload_gen(per_pkt_length)
                            addpkt = pkt / payload
                            isd_dict[i][(srcid, dstid)][-1].append(addpkt)

        if gen_ctrl == False:
            return None, None, gen_ctrl
        else:
            return isd_dict, listenport_dict, gen_ctrl




    gen_ctrl = False

    hostlist = []
    for s in topo_G.nodes():
        try:
            if topo_G.nodes[s]['host'] != []:
                for h in topo_G.nodes[s]['host']:
                    hostlist.append(h)
        except:
            pass

    isd_dict = {i:{(G_to_M(s), G_to_M(d)):[] \
              for d in hostlist for s in hostlist}\
              for i in topo_SLICENDICT.keys()}

    listenport_dict = {}

    if dict_ctrl == "history" or dict_ctrl == "both":
        TRAFFIC = copy.deepcopy(HISTORYTRAFFIC)
        isd_dict, listenport_dict, gen_ctrl = trafficlist_gen(TRAFFIC, isd_dict, listenport_dict, gen_ctrl)
    if dict_ctrl == "extra" or dict_ctrl == "both":
        TRAFFIC = copy.deepcopy(EXTRATRAFFIC)
        isd_dict, listenport_dict, gen_ctrl = trafficlist_gen(TRAFFIC, isd_dict, listenport_dict, gen_ctrl)

    if gen_ctrl == False:
        return None, None, gen_ctrl
    else:
        return isd_dict, listenport_dict, gen_ctrl

# 三種flow
history_flow, listenport_dict, gen_ctrl = host_traffic_gen(hostid, "history")
extra_flow, listenport_dict, gen_ctrl = host_traffic_gen(hostid, "extra")
replay_flow, listenport_dict, gen_ctrl = host_traffic_gen(hostid, "both")

# sniff
def sniff_flow(listen_port):
    #interface_port = "h"+str(hostid)+"-eth0"
    #sniff(iface = interface_port, prn = lambda pkt:pkt.summary())
    print(['iperf', '-s', '-u', '-i', str(1),'-p',str(listen_port)])
    Popen(['iperf', '-s', '-u', '-i', str(1),'-p',str(listen_port)])


#發送flow
"""
###sendp(flow[i][(srcid, dstid)], count = 10, iface = myinterface, verbose = False, socket = myL2socket)
###send(flow[i][(srcid, dstid)], count = 10, iface = myinterface, verbose = False, socket = myL3socket)
###sendpfast(flow[i][(srcid, dstid)], loop = 10, iface = myinterface, file_cache = True)
"""


def send_flow(i, srcid, dstid, flowitem, timestamp, flowtype_ctrl, timeout):
 
    if flowtype_ctrl == "history":
        flow = copy.deepcopy(flowitem)
    elif flowtype_ctrl == "extra":
        flow = copy.deepcopy(flowitem)
    elif flowtype_ctrl == "replay":
        flow = copy.deepcopy(flowitem)

    strpkt=''
    pkt_length = 0
    for pkt in flow:
        strpkt = strpkt+str(len(pkt))+'_'
        pkt_length += int(len(pkt))
    print(f"client {str(hostid)}:start\t{strpkt}")

    """
    scapy
    """
    #myinterface = "h"+str(hostid)+"-eth0"
    #myL2socket = conf.L2socket(iface = myinterface)
    #sendp(flow[i][(srcid, dstid)], iface = myinterface, socket = myL2socket, inter = INNTER_ARRIVAL_TIME[i], count = NUM_PKT[i], verbose = False, realtime=False)

    """
    iperf
    """

    dst_ip = flow[0][IP].dst
    dst_port = flow[0][UDP].dport
    if flowtype_ctrl == "history":
        iperftime = timeout
    elif flowtype_ctrl == "extra":
        iperftime = timeout
    elif flowtype_ctrl == "replay":
        iperftime = TOTAL_TIME
        while (timestamp := time.time()) < GOGO_TIME:
            pass
    #Popen(['iperf', '-c', str(dst_ip), '-p', str(dst_port), '-u', '-i', str(round(INNTER_ARRIVAL_TIME[i], 3)), '-t', str(iperftime), '-l', str(int(pkt_length))])
    Popen(['iperf', '-c', str(dst_ip), '-p', str(dst_port), '-u', '-i', str(round(INNTER_ARRIVAL_TIME[i], 3)), '-t', str(iperftime), '-b', str(int(pkt_length)*8/INNTER_ARRIVAL_TIME[i])])

    print(f'client {str(hostid)}:done\t{str((time.time()-timestamp))}s')


#multithread開生成中有生成的flow
def cnt_flow(timestamp, flow, flowtype_ctrl):

    if flowtype_ctrl == "history":
        timeout = 10 #custom
    elif flowtype_ctrl == "extra":
        timeout = 10 #custom
    elif flowtype_ctrl == "replay":
        timeout = GOGO_TIME-time.time()+TOTAL_TIME

    with ProcessPool() as pool:
        for i, slicedict in flow.items():
            for e, flowlist in slicedict.items():
                if len(flowlist) != []:
                    for flowitem in flowlist:
                        srcid = e[0]
                        dstid = e[1]
                        pool.schedule(send_flow, (i, srcid, dstid, flowitem, timestamp, flowtype_ctrl, timeout), timeout = timeout)

        for listen_port in listenport_dict.keys():
            pool.schedule(sniff_flow, (listen_port, ), timeout = timeout)
        pool.close()
        pool.join()


"""
# 原生pool寫法留存後來改用pebble套件幫忙管理timeout強制關閉
def cnt_flow():
    processlist=[]
    with Pool(processes=cpu_count()) as pool:
        for i, slicedict in flow.items():
            for e, v in slicedict.items():
                srcid=e[0]
                dstid=e[1]
                if len(v) != 0:
                    processlist.append(pool.apply_async(send_flow, (i, srcid, dstid)))
        pool.close()
        pool.join()
"""

#整個flow沒有的話不執行
def main(GOGO_TIME):
    timestamp = GOGO_TIME
    if replay_flow == None and listenport_dict == None:
        print(f"client {str(hostid)}:nothing to send")
    else:
        cnt_flow(timestamp, replay_flow, flowtype_ctrl="replay")

def pre_main():
    timestamp = time.time()
    if history_flow == None:
        print(f"client {str(hostid)}:nothing to presend")
    else:
        cnt_flow(timestamp, history_flow, flowtype_ctrl="history")
    time.sleep(BETWEEN_HISTORY_EXTRA_TIME)
    if extra_flow == None:
        print(f"client {str(hostid)}:nothing to extrasend")
    else:
        cnt_flow(timestamp, extra_flow, flowtype_ctrl="extra")


# 主要執行
if __name__ == "__main__":
    pre_main()
    sleeptime = (GOGO_TIME-time.time()-READPKT_TIME)
    if sleeptime > 2:
        time.sleep(sleeptime)
    main(GOGO_TIME)
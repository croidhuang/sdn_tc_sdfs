# lowletter is used local, could be change
# upperletter link outside, don"t change
# orig_xxx is origin, no orig_xxx is map to pcap file, so "must check" mapping

import time
import math
import random
import pprint

import networkx as nx
import networkx.algorithms.tree.mst as mst
import networkx.algorithms.operators.binary as op
import matplotlib.pyplot as plt

def check_gogo_time(timestring):
    structtime = time.strptime(timestring, "%Y-%m-%d %H:%M:%S")
    timestamp = float(time.mktime(structtime))
    currtime = time.time()

    if timestamp - currtime < 1 * 60:
        print("GG: please config your start time ")
    print(timestamp)

    return timestamp

"""
time
"""

ROUTING_TYPE = "bellman-ford" #bellman-ford, algo
SCHEDULER_TYPE = False  #False,"random","MAX","min","algo"
EXP_TYPE = "routing" #"scheduling","routing", "test"

#seed
RANDOM_SEED_NUM = 3 #custom
random.seed(RANDOM_SEED_NUM)

timestring = "2022-06-05 19:39:00" #custom
timestamp = check_gogo_time(timestring)
GOGO_TIME = timestamp #0,timestamp

#unit is second
TOTAL_TIME = 4 * 60 #custom

#unit is second, monitor period, controller get budget and scheduler distribute
MONITOR_PERIOD = 1 #custom

# custom by your experimnet
# if user > user_threshold will congestion
user_threshold = 1 #custom

# depand on your computer
# if send interval < interval_lowlimit will lag
# ref orig time smallest value would be interval_lowlimit
FIRST_TIME_SLEEP = 10 #custom

#if lower than lowlimit will be lowlimit
interval_lowlimit = float(1/1000) #custom s/packets
interval_lowlimit_ctrl = False

#topology
topo_SLICENDICT = {i:i for i in range(7)} #custom
topo_GNode0_alignto_mininetSwitchNum = 1 #custom

#print all list
print_ctrl = 0





"""
traffic file
"""

#latency, not throughput monitor
CSV_OUTPUTPATH = "./pktgen/timerecord/"


PKT_FILE_LIST = {
    #0chat #1email #2file #3stream #4p2p #5voip #6browser
    0 : "./pktreplay/pcap/aim_chat_3a.pcap",        #0chat
    1 : "./pktreplay/pcap/email1a.pcap",            #1email
    2 : "./pktreplay/pcap/ftps_up_2a.pcap",         #2file
    3 : "./pktreplay/pcap/youtube1.pcap",           #3stream
    4 : "./pktreplay/pcap/Torrent01.pcapng",        #4p2p
    5 : "./pktreplay/pcap/skype_chat1a.pcap",       #5voip
    6 : "./pktreplay/pcap/facebook_chat_4b.pcap",   #6browser
}

"""
traffic file statistics
"""

iter_slice_dict ={
    0: None,
    1: None,
    2: None,
    3: None,
    4: None,
    5: None,
    6: None,
}

#dict statistics from pcap
orig_BW = {
    #avg allbyte/alltime
    #0chat #1email #2file #3stream #4p2p #5voip #6browser
    0: 624,
    1: 4485,
    2: 1029862,
    3: 245670,
    4: 238271,
    5: 14385,
    6: 19673,
}

orig_AVG_INNTER_ARRIVAL_TIME  = {
    #avg alltime/allcount
    0: 0.514901,
    1: 0.510331,
    2: 0.001012,
    3: 0.017945,
    4: 0.003790,
    5: 0.011784,
    6: 0.058626,
}

orig_MEDIAN_INNTER_ARRIVAL_TIME = {
    #median
    #0chat #1email #2file #3stream #4p2p #5voip #6browser
    0: 0.000001,
    1: 0.000009,
    2: 0.000002,
    3: 0.000005,
    4: 0.000026,
    5: 0.000003,
    6: 0.000008,
}

orig_ONE_PKT_SIZE = {
    #median
    #0chat #1email #2file #3stream #4p2p #5voip #6browser
    0: None,
    1: None,
    2: None,
    3: None,
    4: None,
    5: None,
    6: None,
}

orig_AVG_ONE_PKT_SIZE = {
    #cal = avg allbyte/alltime * alltime/allcount
    #0chat #1email #2file #3stream #4p2p #5voip #6browser
    0: 321, 
    1: 2288, 
    2: 1042, 
    3: 4408, 
    4: 903, 
    5: 169, 
    6: 1153,
}

orig_MEDIAN_ONE_PKT_SIZE = {
    #median
    #0chat #1email #2file #3stream #4p2p #5voip #6browser
    0: 92,
    1: 63,
    2: 1514,
    3: 2742,
    4: 1404,
    5: 149,
    6: 146,
}







"""
function
"""

def __INNTER_ARRIVAL_TIME(input_dict,SLICE_TRAFFIC_MAP):
    INNTER_ARRIVAL_TIME = {i: float(input_dict[SLICE_TRAFFIC_MAP[i]]) for i in input_dict}
    if print_ctrl == True:
        print(INNTER_ARRIVAL_TIME) 
    return INNTER_ARRIVAL_TIME

def __ONE_PKT_SIZE(input_dict,SLICE_TRAFFIC_MAP):
    ONE_PKT_SIZE = {i: int(input_dict[SLICE_TRAFFIC_MAP[i]]) for i in input_dict}
    if print_ctrl == True:
        print(ONE_PKT_SIZE) 
    return ONE_PKT_SIZE

def __interval_lowlimit(INNTER_ARRIVAL_TIME):
    x= [v for k, v in sorted(INNTER_ARRIVAL_TIME.items(), key = lambda item:item[1], reverse = False)]
    
    if x[-1]==x[0]:
        normalize_x = 0
    else:
        normalize_x = float( (x[-1]-interval_lowlimit) / (x[-1]-x[0]) )

    for i in INNTER_ARRIVAL_TIME:
        #min = x[1] = interval_lowlimit
        INNTER_ARRIVAL_TIME[i] = float( (INNTER_ARRIVAL_TIME[i]-x[0]) * normalize_x + interval_lowlimit )

    if print_ctrl == True:            
        print(ONE_PKT_SIZE)
        print(INNTER_ARRIVAL_TIME)

    return INNTER_ARRIVAL_TIME

def __EST_SLICE_ONE_PKT (MONITOR_PERIOD, SLICE_TRAFFIC_MAP, INNTER_ARRIVAL_TIME, ONE_PKT_SIZE):
    EST_SLICE_ONE_PKT = {}
    for i in iter_slice_dict:
        c = float(MONITOR_PERIOD / INNTER_ARRIVAL_TIME[SLICE_TRAFFIC_MAP[i]])
        EST_SLICE_ONE_PKT[i] = int(1 * ONE_PKT_SIZE[SLICE_TRAFFIC_MAP[i]] * c)
    if print_ctrl == True:
        print(EST_SLICE_ONE_PKT)    
    return EST_SLICE_ONE_PKT


def __EST_SLICE_AGING (TOTAL_TIME):
    EST_SLICE_AGING = {}
    for i in iter_slice_dict:
        EST_SLICE_AGING[i] = int(TOTAL_TIME)
    if print_ctrl == True:
        print(EST_SLICE_AGING)        
    return EST_SLICE_AGING

def __NUM_PKT (TOTAL_TIME, SLICE_TRAFFIC_MAP, INNTER_ARRIVAL_TIME):
    NUM_PKT = {}
    for i in iter_slice_dict:
        NUM_PKT[i] = int(TOTAL_TIME / INNTER_ARRIVAL_TIME[SLICE_TRAFFIC_MAP[i]])
    if print_ctrl == True:
        print(NUM_PKT)        
    return NUM_PKT

def __MININET_BW (EDGE_BANDWIDTH_G, TOTAL_TIME):
    MININET_BW = {}
    for v1,v2 in EDGE_BANDWIDTH_G.edges():
        c = float(1/TOTAL_TIME)
        MININET_BW[(v1,v2)] = float(EDGE_BANDWIDTH_G[v1][v2]['weight'] * c / (2**20) * 8)
    if print_ctrl == True:
        print(MININET_BW)      
    return MININET_BW


def gen_scaledict(pair_list,traffic_cnt,lowestscale):

    traffic_len = len(traffic_cnt)
    if traffic_len == 0:
        traffic_len = 1             
    traffic_ladder = (1-lowestscale)/ traffic_len

    for ti in range(len(traffic_cnt)):
        traffic_cnt[ti]=1-(traffic_ladder*ti)

    random.shuffle(traffic_cnt)

    scaledict={}
    for ri,r in enumerate(pair_list):
        scaledict[r] = traffic_cnt[ri]  

    return scaledict



#custom
#gen graph
if EXP_TYPE == "test":
    topo_SLICENDICT = {}
    topo_SLICENDICT = {0:0}
    topo_h = 2
    topo_n = 2    
    topo_G = nx.Graph()
    hostlist = [i for i in range(topo_h)]
    nodelist = [i for i in range(topo_n)]
    edgelist = [(0,1)]    
    topo_G.add_nodes_from(nodelist)
    topo_G.add_edges_from(edgelist)
    topo_G.nodes[0]['host'] = [hostlist[0]]
    topo_G.nodes[1]['host'] = [hostlist[1]]

    #hop so weight is 1
    for u,v in topo_G.edges():
        topo_G[u][v]['weight'] = 1

    ####################check####################
    SLICE_TRAFFIC_MAP = {
        #0chat #1email #2file #3stream #4p2p #5voip #6browser
        0: 0,  #0chat
        1: 0,  #0chat
        2: 0,  #0chat
        3: 0,  #0chat
        4: 0,  #0chat
        5: 0,  #0chat
        6: 0,  #0chat
    }
    ####################check####################

    #MUST CHECK you want avg or median
    INNTER_ARRIVAL_TIME = {i: 0.001 for i in iter_slice_dict}
    #MUST CHECK you want avg or median

    #MUST CHECK you want avg or median
    ONE_PKT_SIZE = {i: 8888 for i in iter_slice_dict}
    #MUST CHECK you want avg or median

    """
    cal total packets
    """

    #fit interval_lowlimit
    if interval_lowlimit_ctrl == True:
        INNTER_ARRIVAL_TIME = __interval_lowlimit(INNTER_ARRIVAL_TIME)
    
    NUM_PKT = __NUM_PKT (TOTAL_TIME, SLICE_TRAFFIC_MAP, INNTER_ARRIVAL_TIME)

    """
    cal bandwidth
    """
    
    EST_SLICE_AGING = __EST_SLICE_AGING (TOTAL_TIME)
    EST_SLICE_ONE_PKT =  __EST_SLICE_ONE_PKT (MONITOR_PERIOD, SLICE_TRAFFIC_MAP, INNTER_ARRIVAL_TIME, ONE_PKT_SIZE)

    """
    compatible routing
    """

    HISTORYTRAFFIC = {i:{} for i in topo_SLICENDICT.keys()}
    for i in topo_SLICENDICT.keys():
        HISTORYTRAFFIC[i][(0,1)] = EST_SLICE_AGING[i]

    EDGE_BANDWIDTH_G = topo_G.copy()
    EDGE_BANDWIDTH_G[0][1]['weight'] = EST_SLICE_AGING[0]
    EDGE_BANDWIDTH_G[1][0]['weight'] = EDGE_BANDWIDTH_G[0][1]['weight']

    if print_ctrl == True:
        for v1,v2 in EDGE_BANDWIDTH_G.edges():
            print(EDGE_BANDWIDTH_G[v1][v2]['weight'])

    #mininet unit is MBytes 2^20~1000000, 1Byte = 8bit
    MININET_BW = __MININET_BW (EDGE_BANDWIDTH_G, TOTAL_TIME)



elif EXP_TYPE == "scheduling":

    topo_h = 14
    topo_n = 9    
    topo_G = nx.Graph()
    hostlist = [i for i in range(topo_h)]
    nodelist = [i for i in range(topo_n)]
    edgelist = []    
    for k in topo_SLICENDICT:
        i=k+2
        edgelist.append((0,i))
        edgelist.append((1,i))
    topo_G.add_nodes_from(nodelist)
    topo_G.add_edges_from(edgelist)

    for s in topo_G.nodes():
        topo_G.nodes[s]['host'] = []
    for h in range(0,math.ceil(topo_h/2)):
        topo_G.nodes[0]['host'].append(hostlist[h])
    for h in range(math.ceil(topo_h/2),topo_h):
        topo_G.nodes[1]['host'].append(hostlist[h])

    #hop so weight is 1
    for u,v in topo_G.edges():
        topo_G[u][v]['weight'] = 1

    ####################check####################
    SLICE_TRAFFIC_MAP = {
        #0chat #1email #2file #3stream #4p2p #5voip #6browser
        0: 0,  #0chat
        1: 0,  #0chat
        2: 0,  #0chat
        3: 0,  #0chat
        4: 0,  #0chat
        5: 0,  #0chat
        6: 0,  #0chat
    }
    ####################check####################

    #MUST CHECK you want avg or median
    INNTER_ARRIVAL_TIME = __INNTER_ARRIVAL_TIME(orig_AVG_INNTER_ARRIVAL_TIME,SLICE_TRAFFIC_MAP)
    #MUST CHECK you want avg or median

    #MUST CHECK you want avg or median
    ONE_PKT_SIZE = __ONE_PKT_SIZE(orig_AVG_ONE_PKT_SIZE, SLICE_TRAFFIC_MAP)
    #MUST CHECK you want avg or median

    """
    cal total packets
    """

    #fit interval_lowlimit
    if interval_lowlimit_ctrl == True:
        INNTER_ARRIVAL_TIME = __interval_lowlimit(INNTER_ARRIVAL_TIME)

    NUM_PKT = __NUM_PKT (TOTAL_TIME, SLICE_TRAFFIC_MAP, INNTER_ARRIVAL_TIME)

    """
    cal bandwidth
    """

    EST_SLICE_AGING = __EST_SLICE_AGING (TOTAL_TIME)
    EST_SLICE_ONE_PKT =  __EST_SLICE_ONE_PKT (MONITOR_PERIOD, SLICE_TRAFFIC_MAP, INNTER_ARRIVAL_TIME, ONE_PKT_SIZE)

    """
    compatible routing
    """

    HISTORYTRAFFIC = {i:{} for i in topo_SLICENDICT.keys()}
    for i in topo_SLICENDICT.keys():
        HISTORYTRAFFIC[i][(0,1)] = EST_SLICE_ONE_PKT[i]

    EDGE_BANDWIDTH_G = topo_G.copy()
    for k in topo_SLICENDICT:
        i=k+2
        EDGE_BANDWIDTH_G[0][i]['weight'] = EST_SLICE_ONE_PKT[i-2]
        EDGE_BANDWIDTH_G[i][0]['weight'] = EDGE_BANDWIDTH_G[0][i]['weight']
        EDGE_BANDWIDTH_G[1][i]['weight'] = EST_SLICE_ONE_PKT[i-2]
        EDGE_BANDWIDTH_G[i][1]['weight'] = EDGE_BANDWIDTH_G[1][i]['weight']

    if print_ctrl == True:
        for v1,v2 in EDGE_BANDWIDTH_G.edges():
            print(EDGE_BANDWIDTH_G[v1][v2]['weight'])

    #mininet unit is MBytes 2^20~1000000, 1Byte = 8bit
    MININET_BW = __MININET_BW (EDGE_BANDWIDTH_G, TOTAL_TIME)   



#custom
#gen graph
if EXP_TYPE == "routing":

    topo_h = 7
    topo_n = 7   

    #exp var ratio
    historytraffic_send_ratio = 0.8 #custom
    historytraffic_scale = 0.8 #custom 
    edge_bandwidth_scale = 0.8 #custom

    topo_G = nx.Graph()
    hostlist = [i for i in range(topo_h)]
    nodelist = [i for i in range(topo_n)]
    edgelist = []
    for u in range(topo_n):
        for v in range(topo_n):
            if u<v:
                edgelist.append((u,v))

    topo_G.add_nodes_from(nodelist)
    topo_G.add_edges_from(edgelist)

    for s in topo_G.nodes():
        topo_G.nodes[s]['host'] = []
    for h in hostlist:
        try:
            topo_G.nodes[h]['host'].append(hostlist[h])
        except:
            print("gg: host > switch")

    #hop so weight is 1
    for u,v in topo_G.edges():
        topo_G[u][v]['weight'] = 1
    
    ####################check####################
    SLICE_TRAFFIC_MAP = {
        #0chat #1email #2file #3stream #4p2p #5voip #6browser
        0: 0,  #0chat
        1: 1,  #1email
        2: 2,  #2file
        3: 3,  #3stream
        4: 4,  #4p2p
        5: 5,  #5voip
        6: 6,  #6browser
    }
    ####################check####################
    
    #MUST CHECK you want avg or median
    INNTER_ARRIVAL_TIME = __INNTER_ARRIVAL_TIME(orig_AVG_INNTER_ARRIVAL_TIME,SLICE_TRAFFIC_MAP)
    #MUST CHECK you want avg or median

    #MUST CHECK you want avg or median
    ONE_PKT_SIZE = __ONE_PKT_SIZE(orig_AVG_ONE_PKT_SIZE, SLICE_TRAFFIC_MAP)
    #MUST CHECK you want avg or median

    """
    cal total packets
    """

    #fit interval_lowlimit
    if interval_lowlimit_ctrl == True:
        INNTER_ARRIVAL_TIME = __interval_lowlimit(INNTER_ARRIVAL_TIME)

    NUM_PKT = __NUM_PKT (TOTAL_TIME, SLICE_TRAFFIC_MAP, INNTER_ARRIVAL_TIME)

    """
    traffic generate
    """

    HISTORYTRAFFIC = {i:{} for i in topo_SLICENDICT.keys()}
    for i,i_dict in HISTORYTRAFFIC.items():
        for v1 in topo_G.nodes():
            for v2 in topo_G.nodes():
                if v1 != v2:
                    #0.5 is only one direction
                    if random.random() > 0.5:
                        HISTORYTRAFFIC[i][(v1,v2)] = 0
                    else:
                        HISTORYTRAFFIC[i][(v2,v1)] = 0

    sum_HISTORYTRAFFIC = 0
    sum_SLICE_HISTORYTRAFFIC = {i:0 for i in topo_SLICENDICT.keys()}
    num_SLICE_HISTORYTRAFFIC = {i:0 for i in topo_SLICENDICT.keys()}
    
    for i,i_dict in HISTORYTRAFFIC.items():
        pair_list=[]
        traffic_cnt=[]        
        for e,v in i_dict.items():         
            if random.random() > historytraffic_send_ratio:
                continue
            else:                
                pair_list.append(e)
                traffic_cnt.append(0)

            scaledict = gen_scaledict(pair_list,traffic_cnt,historytraffic_scale)            

            for pi,e in enumerate(pair_list):
                v1=e[0]
                v2=e[1]
                HISTORYTRAFFIC[i][(v1,v2)] = int(\
                    ONE_PKT_SIZE[SLICE_TRAFFIC_MAP[i]] * \
                    float(1/INNTER_ARRIVAL_TIME[SLICE_TRAFFIC_MAP[i]]) * \
                    TOTAL_TIME* \
                    scaledict[e])
                sum_HISTORYTRAFFIC = sum_HISTORYTRAFFIC + HISTORYTRAFFIC[i][(v1,v2)]
                sum_SLICE_HISTORYTRAFFIC[i] = sum_SLICE_HISTORYTRAFFIC[i] + HISTORYTRAFFIC[i][(v1,v2)]
                num_SLICE_HISTORYTRAFFIC[i] = num_SLICE_HISTORYTRAFFIC[i] + 1
    if print_ctrl == True:
        pprint.pprint(HISTORYTRAFFIC)

    """
    cal bandwidth
    """

    EDGE_BANDWIDTH_G = topo_G.copy()
    for v1,v2 in EDGE_BANDWIDTH_G.edges():
        EDGE_BANDWIDTH_G[v1][v2]['weight'] = 0
        EDGE_BANDWIDTH_G[v2][v1]['weight'] = EDGE_BANDWIDTH_G[v1][v2]['weight']         

    pers_b = sum_HISTORYTRAFFIC / TOTAL_TIME
    if int(pers_b/(2**20)) >2700:
        print(f"{pers_b/(2**20)}>2700")
    else:
        print(f"{pers_b/(2**20)}<2700")

    edge_num = len(EDGE_BANDWIDTH_G.edges())
    avg_b = sum_HISTORYTRAFFIC / edge_num 

    pair_list=[]
    traffic_cnt=[]        
    for v1,v2 in EDGE_BANDWIDTH_G.edges():
        e=(v1,v2)
        pair_list.append(e)
        traffic_cnt.append(0)

    scaledict = gen_scaledict(pair_list,traffic_cnt,edge_bandwidth_scale)     

    for v1,v2 in EDGE_BANDWIDTH_G.edges():
        e=(v1,v2)
        EDGE_BANDWIDTH_G[v1][v2]['weight'] = int(avg_b*scaledict[e])
        EDGE_BANDWIDTH_G[v2][v1]['weight'] = EDGE_BANDWIDTH_G[v1][v2]['weight']      

    if print_ctrl == True:
        for v1,v2 in EDGE_BANDWIDTH_G.edges():
            print(EDGE_BANDWIDTH_G[v1][v2]['weight'])

    EST_SLICE_AGING = __EST_SLICE_AGING (TOTAL_TIME)
    EST_SLICE_ONE_PKT =  __EST_SLICE_ONE_PKT (MONITOR_PERIOD, SLICE_TRAFFIC_MAP, INNTER_ARRIVAL_TIME, ONE_PKT_SIZE)

    #mininet unit is MBytes 2^20~1000000, 1Byte = 8bit
    MININET_BW = __MININET_BW (EDGE_BANDWIDTH_G, TOTAL_TIME)
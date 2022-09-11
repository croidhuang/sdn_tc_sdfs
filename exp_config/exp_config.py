# lowletter is used local, could be change
# upperletter link outside, don"t change
# orig_xxx is origin, no orig_xxx is map to pcap file, so "must check" mapping

import time
import math
import random
import pprint
import copy
import json
import os

import networkx as nx
import networkx.algorithms.tree.mst as mst
import networkx.algorithms.operators.binary as op
import matplotlib.pyplot as plt




"""
time
"""

username='croid'
homedir = os.path.expanduser('~'+username)
try:
    exp_iter = json.load(open(homedir+"/exp_iter.txt"))
except:
    print('change config username')



def check_gogo_time(timestring,immediate_start):
    structtime = time.strptime(timestring, "%Y-%m-%d %H:%M:%S")
    timestamp = float(time.mktime(structtime))
    if timestamp - immediate_start < 0:
        timestamp = immediate_start
        print("GG: please config your start time ")
    else:
        print(f'GOGO_TIME: {timestring}')
    return timestamp



#seed
RANDOM_SEED_NUM = 3 #custom
random.seed(RANDOM_SEED_NUM)

# timetosleep
READPKT_TIME = 5
RYUSTART_TIME = 15
BETWEEN_HISTORY_EXTRA_TIME = 5
other_time = 5



#iter
ROUTING_TYPE = exp_iter['ROUTING_TYPE']    
SCHEDULER_TYPE = exp_iter['SCHEDULER_TYPE']   
EXP_TYPE =  exp_iter['EXP_TYPE']  
DYNBW_TYPE = exp_iter['DYNBW_TYPE']  

timestring = exp_iter['timestring'] 

immediate_start = time.time()+ READPKT_TIME + RYUSTART_TIME + BETWEEN_HISTORY_EXTRA_TIME + other_time
GOGO_TIME = check_gogo_time(timestring,immediate_start)

#unit is second
TOTAL_TIME = 4*60 #custom

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
topo_SLICENDICT = {i:i for i in range(2)} #custom
topo_GNode0_alignto_mininetSwitchNum = 1 #custom

#print all list
print_ctrl = 0


#0stream #1voip #2chat #3browser #4email #5p2p #6file

#HW limit
#cfs     50%     4.10e+10
mininet_cpu_py = (4.10e+10)
mininet_cpu_py = mininet_cpu_py/8/(2**20)

network_card_io = (100e+6)
network_card_io = network_card_io /8/(2**20)

sata2_io = (3.0e+9)
sata2_io = sata2_io/8/(2**20)

hw_limit=min([mininet_cpu_py,network_card_io,sata2_io ])
print(hw_limit)

"""
traffic file
"""

#latency, not throughput monitor
CSV_OUTPUTPATH = "./pktgen/timerecord/"


PKT_FILE_LIST = {
    #0chat #1email #2file #3stream #4p2p #5voip #6browser
    0 : "./pktreplay/pcap/aim_chat_3a.pcap", #0chat
    1 : "./pktreplay/pcap/email1a.pcap", #1email
    2 : "./pktreplay/pcap/ftps_up_2a.pcap", #2file
    3 : "./pktreplay/pcap/youtube1.pcap", #3stream
    4 : "./pktreplay/pcap/Torrent01.pcapng", #4p2p
    5 : "./pktreplay/pcap/skype_chat1a.pcap", #5voip
    6 : "./pktreplay/pcap/facebook_chat_4b.pcap", #6browser
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


test_AVG_ONE_PKT_SIZE = {
    #cal = avg allbyte/alltime * alltime/allcount
    #0chat #1email #2file #3stream #4p2p #5voip #6browser
    0: 321,
    1: 321,
    2: 321,
    3: 321,
    4: 321,
    5: 321,
    6: 321,
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

def __INNTER_ARRIVAL_TIME(input_dict, SLICE_TRAFFIC_MAP):
    INNTER_ARRIVAL_TIME = {i: float(input_dict[SLICE_TRAFFIC_MAP[i]]) for i in input_dict}
    if print_ctrl == True:
        print(INNTER_ARRIVAL_TIME)
    return INNTER_ARRIVAL_TIME

def __ONE_PKT_SIZE(input_dict, SLICE_TRAFFIC_MAP):
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
        ###min = x[1] = interval_lowlimit
        INNTER_ARRIVAL_TIME[i] = float( (INNTER_ARRIVAL_TIME[i]-x[0]) * normalize_x + interval_lowlimit )

    if print_ctrl == True:
        print(ONE_PKT_SIZE)
        print(INNTER_ARRIVAL_TIME)

    return INNTER_ARRIVAL_TIME

def __EST_SLICE_ONE_PKT (MONITOR_PERIOD, INNTER_ARRIVAL_TIME, ONE_PKT_SIZE):
    EST_SLICE_ONE_PKT = {}
    for i in iter_slice_dict:
        c = float(MONITOR_PERIOD / INNTER_ARRIVAL_TIME[i])
        EST_SLICE_ONE_PKT[i] = int(1 * ONE_PKT_SIZE[i] * c)
    if print_ctrl == True:
        print(EST_SLICE_ONE_PKT)
    return EST_SLICE_ONE_PKT

def __EST_SLICE_RATIO (MONITOR_PERIOD, EST_SLICE_ONE_PKT):
    EST_SLICE_RATIO = {}
    sum = 0
    for i in iter_slice_dict:
        sum += EST_SLICE_ONE_PKT[i]
    for i in iter_slice_dict:
        EST_SLICE_RATIO[i] = EST_SLICE_ONE_PKT[i] / sum
    if print_ctrl == True:
        print(EST_SLICE_RATIO)
    return EST_SLICE_RATIO

def __EST_SLICE_AGING (TOTAL_TIME):
    EST_SLICE_AGING = {}
    for i in iter_slice_dict:
        EST_SLICE_AGING[i] = int(TOTAL_TIME)
    if print_ctrl == True:
        print(EST_SLICE_AGING)
    return EST_SLICE_AGING

def __NUM_PKT (TOTAL_TIME, INNTER_ARRIVAL_TIME):
    NUM_PKT = {}
    for i in iter_slice_dict:
        NUM_PKT[i] = int(TOTAL_TIME / INNTER_ARRIVAL_TIME[i])
    if print_ctrl == True:
        print(NUM_PKT)
    return NUM_PKT

def __MININET_BW (EDGE_BANDWIDTH_G):
    MININET_BW = {}
    for v1, v2 in EDGE_BANDWIDTH_G.edges():
        c = 1
        #mininet unit is Mbit, M = 1000000(not 2**20 here), 1Byte = 8bit
        MININET_BW[(v1, v2)] = round(EDGE_BANDWIDTH_G[v1][v2]['weight'] * c / (2**20) * 8,5)
    if print_ctrl == True:
        print(MININET_BW)
    return MININET_BW

   
def __gen_scaledict(pair_list, traffic_cnt, lowestscale, shuffle):
    traffic_len = len(traffic_cnt)
    if traffic_len == 0:
        traffic_len = 1
    traffic_ladder = (1-lowestscale)/ traffic_len

    for ti in range(len(traffic_cnt)):
        traffic_cnt[ti]=1-(traffic_ladder*ti)

    if shuffle == True:
        random.shuffle(traffic_cnt)

    scaledict={}
    for ri, r in enumerate(pair_list):
        scaledict[r] = traffic_cnt[ri]

    return scaledict

def __SLICE_TRAFFIC_NORMALNUM(historytraffic_send_ratio, SLICE_TRAFFIC_NUM):
    slice_n = topo_e*len(topo_SLICENDICT)*historytraffic_send_ratio

    sum_slice = 0
    for k, v in SLICE_TRAFFIC_NUM.items():
        sum_slice += v
    if sum_slice == 0:
       sum_slice = 1

    SLICE_TRAFFIC_NORMALNUM = {i:0 for i in topo_SLICENDICT.keys()}
    for k,v in SLICE_TRAFFIC_NORMALNUM.items():
        SLICE_TRAFFIC_NORMALNUM[k] = round((SLICE_TRAFFIC_NUM[k]/sum_slice)*slice_n)
        
    return SLICE_TRAFFIC_NORMALNUM

def int_round(num,hold):
    if len(str((int(num)))) <= hold:
        return int(num)
    else:
        num_len = len(str((int(num))))
        round_len = num_len - hold
        return int(str(num)[:hold])*(10**round_len)


#custom
#gen graph
if EXP_TYPE == "scheduling_routing":
    print("scheduling_routing")

    topo_h = 14
    topo_n = 9
    topo_G = nx.Graph()
    hostlist = [i for i in range(topo_h)]
    nodelist = [i for i in range(topo_n)]
    edgelist = []
    for k in topo_SLICENDICT:
        i=k+2
        edgelist.append((0, i))
        edgelist.append((1, i))
    topo_G.add_nodes_from(nodelist)
    topo_G.add_edges_from(edgelist)

    for s in topo_G.nodes():
        topo_G.nodes[s]['host'] = []
    for h in range(0, math.ceil(topo_h/2)):
        topo_G.nodes[0]['host'].append(hostlist[h])
    for h in range(math.ceil(topo_h/2), topo_h):
        topo_G.nodes[1]['host'].append(hostlist[h])

    #hop so weight is 1
    for u, v in topo_G.edges():
        topo_G[u][v]['weight'] = 1

    ####################check####################
    # sort long to short for test
    SLICE_TRAFFIC_MAP = {
        #0chat #1email #2file #3stream #4p2p #5voip #6browser
        0: 1,
        1: 1,
        2: 1,
        3: 1,
        4: 1,
        5: 1,
        6: 0,
    }
    """
    0: 624,
    1: 4485,
    2: 1029862,
    3: 245670,
    4: 238271,
    5: 14385,
    6: 19673,
    """
    ####################check####################

    #MUST CHECK you want avg or median
    INNTER_ARRIVAL_TIME = __INNTER_ARRIVAL_TIME(orig_AVG_INNTER_ARRIVAL_TIME, SLICE_TRAFFIC_MAP)
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

    NUM_PKT = __NUM_PKT (TOTAL_TIME, INNTER_ARRIVAL_TIME)

    """
    traffic generate
    """

    """
    cal bandwidth
    """

    EST_SLICE_AGING = __EST_SLICE_AGING (TOTAL_TIME)
    EST_SLICE_ONE_PKT =  __EST_SLICE_ONE_PKT (MONITOR_PERIOD, INNTER_ARRIVAL_TIME, ONE_PKT_SIZE)

    """
    compatible routing
    """

    HISTORYTRAFFIC = {i:{} for i in topo_SLICENDICT.keys()}

    #directed, not edge, host to host
    for i, i_dict in HISTORYTRAFFIC.items():
        for v1 in topo_G.nodes():
            for v2 in topo_G.nodes():
                if v1 != v2:
                    #0.5 is only one direction
                    if v1 < v2 :
                        try:
                            if bool(HISTORYTRAFFIC[i][(v2,v1)]) == True:
                                pass
                        except:
                            HISTORYTRAFFIC[i][(v1, v2)] = 0


    #gen and sum traffic
    sum_HISTORYTRAFFIC = 0
    cnt_HISTORYTRAFFIC = 0
    check_TRAFFIC=0
    x_HISTORYTRAFFIC = {i:0 for i in topo_SLICENDICT.keys()}
    for i, i_dict in HISTORYTRAFFIC.items():
        v1=i
        v2=i+len(topo_SLICENDICT)
        HISTORYTRAFFIC[i][(v1, v2)] = int(\
            ONE_PKT_SIZE[i] * \
            float(1/INNTER_ARRIVAL_TIME[i]))
        sum_HISTORYTRAFFIC += HISTORYTRAFFIC[i][(v1, v2)]
        check_TRAFFIC += HISTORYTRAFFIC[i][(v1, v2)]
        cnt_HISTORYTRAFFIC += 1
        x_HISTORYTRAFFIC[i]+= 1

    if print_ctrl == True:
        pprint.pprint(HISTORYTRAFFIC)
        print(sum_HISTORYTRAFFIC)
        print(cnt_HISTORYTRAFFIC)

    EXTRATRAFFIC = copy.deepcopy(HISTORYTRAFFIC)
    for i, i_dict in EXTRATRAFFIC.items():
        for v1,v2 in i_dict.keys():
            EXTRATRAFFIC[i][(v1, v2)] = 0

    for vi in range(5):
        v1 = vi
        v2 = vi+len(topo_SLICENDICT)
        EXTRATRAFFIC[6][(v1, v2)] = int(\
            ONE_PKT_SIZE[6] * \
            float(1/INNTER_ARRIVAL_TIME[6]))+int(6-vi)
        check_TRAFFIC += EXTRATRAFFIC[6][(v1, v2)]

    check_TRAFFIC = check_TRAFFIC*TOTAL_TIME
    """
    cal bandwidth
    """
    
    if int(sum_HISTORYTRAFFIC/(2**20)) > hw_limit:
        print(f"{sum_HISTORYTRAFFIC/(2**20)}>{hw_limit}")
    else:
        print(f"{sum_HISTORYTRAFFIC/(2**20)}<={hw_limit}")

    python_multiprocess = 8*4 #custom at least 2
    if int(cnt_HISTORYTRAFFIC) > python_multiprocess:
        print(f"{cnt_HISTORYTRAFFIC}>{python_multiprocess}")
    else:
        print(f"{cnt_HISTORYTRAFFIC}<={python_multiprocess}")


    EDGE_BANDWIDTH_G = topo_G.copy()
    for v1, v2 in EDGE_BANDWIDTH_G.edges():
        EDGE_BANDWIDTH_G[v1][v2]['weight'] = 0
        EDGE_BANDWIDTH_G[v2][v1]['weight'] = EDGE_BANDWIDTH_G[v1][v2]['weight']

    #gen
    for k in topo_SLICENDICT:
        i=k+2
        if k != 6:
            EDGE_BANDWIDTH_G[0][i]['weight'] = EST_SLICE_ONE_PKT[i-2]*x_HISTORYTRAFFIC[k]+EST_SLICE_ONE_PKT[6]
            EDGE_BANDWIDTH_G[i][0]['weight'] = EDGE_BANDWIDTH_G[0][i]['weight']
            EDGE_BANDWIDTH_G[1][i]['weight'] = EST_SLICE_ONE_PKT[i-2]*x_HISTORYTRAFFIC[k]+EST_SLICE_ONE_PKT[6]
            EDGE_BANDWIDTH_G[i][1]['weight'] = EDGE_BANDWIDTH_G[1][i]['weight']
        else:
            EDGE_BANDWIDTH_G[0][i]['weight'] = EST_SLICE_ONE_PKT[6]+1
            EDGE_BANDWIDTH_G[i][0]['weight'] = EDGE_BANDWIDTH_G[0][i]['weight']
            EDGE_BANDWIDTH_G[1][i]['weight'] = EST_SLICE_ONE_PKT[6]+1
            EDGE_BANDWIDTH_G[i][1]['weight'] = EDGE_BANDWIDTH_G[1][i]['weight']

    if print_ctrl == True:
        for v1, v2 in EDGE_BANDWIDTH_G.edges():
            print(f"({v1},{v2}):{EDGE_BANDWIDTH_G[v1][v2]['weight']}")

    #aging
    EST_SLICE_AGING = __EST_SLICE_AGING (TOTAL_TIME)
    EST_SLICE_ONE_PKT =  __EST_SLICE_ONE_PKT (MONITOR_PERIOD, INNTER_ARRIVAL_TIME, ONE_PKT_SIZE)

    MININET_BW = __MININET_BW (EDGE_BANDWIDTH_G)



elif EXP_TYPE == "scheduling":
    print("scheduling")

    topo_h = 14
    topo_n = 9
    topo_G = nx.Graph()
    hostlist = [i for i in range(topo_h)]
    nodelist = [i for i in range(topo_n)]
    edgelist = []
    for k in topo_SLICENDICT:
        i=k+2
        edgelist.append((0, i))
        edgelist.append((1, i))
    topo_G.add_nodes_from(nodelist)
    topo_G.add_edges_from(edgelist)

    for s in topo_G.nodes():
        topo_G.nodes[s]['host'] = []
    for h in range(0, math.ceil(topo_h/2)):
        topo_G.nodes[0]['host'].append(hostlist[h])
    for h in range(math.ceil(topo_h/2), topo_h):
        topo_G.nodes[1]['host'].append(hostlist[h])

    #hop so weight is 1
    for u, v in topo_G.edges():
        topo_G[u][v]['weight'] = 1

    ####################check####################
    SLICE_TRAFFIC_MAP = {
        #0chat #1email #2file #3stream #4p2p #5voip #6browser
        0: 0, #0chat
        1: 0, #0chat
        2: 0, #0chat
        3: 0, #0chat
        4: 0, #0chat
        5: 0, #0chat
        6: 0, #0chat
    }
    ####################check####################

    #MUST CHECK you want avg or median
    INNTER_ARRIVAL_TIME = __INNTER_ARRIVAL_TIME(orig_AVG_INNTER_ARRIVAL_TIME, SLICE_TRAFFIC_MAP)
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

    NUM_PKT = __NUM_PKT (TOTAL_TIME, INNTER_ARRIVAL_TIME)

    """
    cal bandwidth
    """

    EST_SLICE_AGING = __EST_SLICE_AGING (TOTAL_TIME)
    EST_SLICE_ONE_PKT =  __EST_SLICE_ONE_PKT (MONITOR_PERIOD, INNTER_ARRIVAL_TIME, ONE_PKT_SIZE)

    """
    compatible routing
    """

    HISTORYTRAFFIC = {i:{} for i in topo_SLICENDICT.keys()}
    for i in topo_SLICENDICT.keys():
        HISTORYTRAFFIC[i][(0, 1)] = EST_SLICE_ONE_PKT[i]

    EDGE_BANDWIDTH_G = topo_G.copy()
    for k in topo_SLICENDICT:
        i=k+2
        EDGE_BANDWIDTH_G[0][i]['weight'] = EST_SLICE_ONE_PKT[i-2]
        EDGE_BANDWIDTH_G[i][0]['weight'] = EDGE_BANDWIDTH_G[0][i]['weight']
        EDGE_BANDWIDTH_G[1][i]['weight'] = EST_SLICE_ONE_PKT[i-2]
        EDGE_BANDWIDTH_G[i][1]['weight'] = EDGE_BANDWIDTH_G[1][i]['weight']

    if print_ctrl == True:
        for v1, v2 in EDGE_BANDWIDTH_G.edges():
            print(EDGE_BANDWIDTH_G[v1][v2]['weight'])

    MININET_BW = __MININET_BW (EDGE_BANDWIDTH_G)



#custom
#gen graph
elif EXP_TYPE == "routing":
    print("routing")

    topo_h = len(topo_SLICENDICT)
    topo_n = len(topo_SLICENDICT)
    topo_e = (topo_n-1)*topo_n

    #exp var ratio
    edge_min_connect = 3 #custom at least 1 connect
    python_multiprocess = 4*4 #custom at least 2
    historytraffic_send_ratio = python_multiprocess/(topo_e*len(topo_SLICENDICT)) #custom
    historytraffic_scale = 0.8 #custom
    edge_bandwidth_scale = 0.8 #custom

    topo_G = nx.Graph()
    hostlist = [i for i in range(topo_h)]
    nodelist = [i for i in range(topo_n)]

    #random edgelist
    edgedict = {(u, v):0 for u in nodelist for v in nodelist}
    edgecntdict={u:0 for u in nodelist}
    for u in nodelist:
        # ensure connect
        choice_node_list = list(nodelist.copy())
        choice_node_list = [v for v in choice_node_list if v != u]
        fixed_connect_v_list = random.sample(choice_node_list, 1)
        choice_node_list = [v for v in choice_node_list if v not in fixed_connect_v_list]
        try:
            other_connect_v_range = random.randrange(int(edge_min_connect-1),int(topo_n/2))
        except:
            other_connect_v_range = 1
        try:
            other_connect_v_list = random.sample(set(choice_node_list), other_connect_v_range)
        except:
            other_connect_v_list = choice_node_list

        # random add edge u>v only (u, v) no (v, u)
        for v in nodelist:
            if  v in fixed_connect_v_list:
                if u<v:
                    edgedict[(u, v)]+=1
                elif v<u:
                    edgedict[(v, u)]+=1
            elif v in other_connect_v_list:
                if u<v:
                    edgedict[(u, v)]+=1
                elif v<u:
                    edgedict[(v, u)]+=1
    edgelist=[k for k, v in edgedict.items() if v!=0]
    edge_num = len(edgelist)

    edgecountdict = copy.deepcopy(edgedict)
    edge_num = 0
    for k,v in edgecountdict.items():
        n1=k[0]
        n2=k[1]
        if v != 0 and (k in edgelist):
            edge_num += 1
            edgecountdict[(n1,n2)]=0
            edgecountdict[(n2,n1)]=0



    topo_G.add_nodes_from(nodelist)
    topo_G.add_edges_from(edgelist)

    #networkx no host, so add host label
    for s in topo_G.nodes():
        topo_G.nodes[s]['host'] = []
    for h in hostlist:
        try:
            topo_G.nodes[h]['host'].append(hostlist[h])
        except:
            print("gg: host > switch")

    #hop so weight is 1
    for u, v in topo_G.edges():
        topo_G[u][v]['weight'] = 1

    ####################check####################
    SLICE_TRAFFIC_MAP = {
        #0chat #1email #2file #3stream #4p2p #5voip #6browser
        0: 3, #3stream
        1: 5, #5voip
        2: 0, #0chat
        3: 6, #6browser
        4: 1, #1email
        5: 2, #2file
        6: 4, #4p2p
    }
    ####################check####################

    ####################check####################
    SLICE_TRAFFIC_NUM = {
        #0chat #1email #2file #3stream #4p2p #5voip #6browser
        0: 2, #3stream
        1: 4, #5voip
        2: 20, #0chat
        3: 3, #6browser
        4: 2, #1email
        5: 0, #2file
        6: 2, #4p2p
    }
    ####################check####################

    SLICE_TRAFFIC_NORMALNUM = __SLICE_TRAFFIC_NORMALNUM(historytraffic_send_ratio, SLICE_TRAFFIC_NUM)


    #MUST CHECK you want avg or median
    INNTER_ARRIVAL_TIME = __INNTER_ARRIVAL_TIME(orig_AVG_INNTER_ARRIVAL_TIME, SLICE_TRAFFIC_MAP)
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

    NUM_PKT = __NUM_PKT (TOTAL_TIME, INNTER_ARRIVAL_TIME)

    """
    traffic generate
    """

    HISTORYTRAFFIC = {i:{} for i in topo_SLICENDICT.keys()}

    #directed, not edge, host to host
    for i, i_dict in HISTORYTRAFFIC.items():
        for v1 in topo_G.nodes():
            for v2 in topo_G.nodes():
                if v1 != v2:
                    #0.5 is only one direction
                    if random.random() > 0.5 :
                        try:
                            if bool(HISTORYTRAFFIC[i][(v2,v1)]) == True:
                                pass
                        except:
                            HISTORYTRAFFIC[i][(v1, v2)] = 0
                    else:
                        try:
                            if bool(HISTORYTRAFFIC[i][(v1,v2)]) == True:
                                pass
                        except:
                            HISTORYTRAFFIC[i][(v2, v1)] = 0


    #gen and sum traffic
    sum_HISTORYTRAFFIC = 0
    cnt_HISTORYTRAFFIC = 0
    check_TRAFFIC=0
    for i, i_dict in HISTORYTRAFFIC.items():
        pair_list=[]
        traffic_cnt=[]
        # send ratio
        send_list=[e for e in i_dict.keys()]
        if len(send_list) >= SLICE_TRAFFIC_NORMALNUM[i]:
            choice_send_list = random.sample(send_list, SLICE_TRAFFIC_NORMALNUM[i])
        else:
            choice_send_list = send_list
        #shuffle list
        for e in i_dict.keys():
            if e in choice_send_list:
                pair_list.append(e)
                traffic_cnt.append(0)
            scaledict = __gen_scaledict(pair_list, traffic_cnt, historytraffic_scale,shuffle=True)
        #gen
        for p in pair_list:
            v1=p[0]
            v2=p[1]
            HISTORYTRAFFIC[i][(v1, v2)] = int(\
                ONE_PKT_SIZE[i] * \
                float(1/INNTER_ARRIVAL_TIME[i]) * \
                scaledict[p])
            sum_HISTORYTRAFFIC += HISTORYTRAFFIC[i][(v1, v2)]
            check_TRAFFIC += HISTORYTRAFFIC[i][(v1, v2)]
            cnt_HISTORYTRAFFIC += 1

    if print_ctrl == True:
        pprint.pprint(HISTORYTRAFFIC)
        print(sum_HISTORYTRAFFIC)
        print(cnt_HISTORYTRAFFIC)

    EXTRATRAFFIC = copy.deepcopy(HISTORYTRAFFIC)
    for i, i_dict in EXTRATRAFFIC.items():
        for v1,v2 in i_dict.keys():
            EXTRATRAFFIC[i][(v1, v2)] = 0
            check_TRAFFIC += EXTRATRAFFIC[i][(v1, v2)]

    check_TRAFFIC=check_TRAFFIC*TOTAL_TIME

    """
    cal bandwidth
    """

    if int(sum_HISTORYTRAFFIC/(2**20)) > hw_limit:
        print(f"{sum_HISTORYTRAFFIC/(2**20)}>{hw_limit}")
    else:
        print(f"{sum_HISTORYTRAFFIC/(2**20)}<={hw_limit}")

    if int(cnt_HISTORYTRAFFIC) > python_multiprocess:
        print(f"{cnt_HISTORYTRAFFIC}>{python_multiprocess}")
    else:
        print(f"{cnt_HISTORYTRAFFIC}<={python_multiprocess}")


    EDGE_BANDWIDTH_G = topo_G.copy()
    for v1, v2 in EDGE_BANDWIDTH_G.edges():
        EDGE_BANDWIDTH_G[v1][v2]['weight'] = 0
        EDGE_BANDWIDTH_G[v2][v1]['weight'] = EDGE_BANDWIDTH_G[v1][v2]['weight']

    #shuffle bandwidth
    pair_list=[]
    traffic_cnt=[]
    for v1, v2 in EDGE_BANDWIDTH_G.edges():
        e = (v1, v2)
        pair_list.append(e)
        traffic_cnt.append(0)
    scaledict = __gen_scaledict(pair_list, traffic_cnt, edge_bandwidth_scale,shuffle=True)
    #gen
    avg_b = sum_HISTORYTRAFFIC / edge_num
    for v1, v2 in EDGE_BANDWIDTH_G.edges():
        e = (v1, v2)
        EDGE_BANDWIDTH_G[v1][v2]['weight'] = int(avg_b*scaledict[e])
        EDGE_BANDWIDTH_G[v2][v1]['weight'] = EDGE_BANDWIDTH_G[v1][v2]['weight']

    if print_ctrl == True:
        for v1, v2 in EDGE_BANDWIDTH_G.edges():
            print(f"({v1},{v2}):{EDGE_BANDWIDTH_G[v1][v2]['weight']}")

    #aging
    EST_SLICE_AGING = __EST_SLICE_AGING (TOTAL_TIME)
    EST_SLICE_ONE_PKT =  __EST_SLICE_ONE_PKT (MONITOR_PERIOD, INNTER_ARRIVAL_TIME, ONE_PKT_SIZE)

    MININET_BW = __MININET_BW (EDGE_BANDWIDTH_G)



#custom
#gen graph
elif EXP_TYPE == "square_routing":
    print("square_routing")

    topo_h = 4
    topo_n = 4
    topo_e = (topo_n-1)*topo_n

    #exp var ratio
    edge_min_connect = 3 #custom at least 1 connect
    python_multiprocess = 4*3 #custom at least 2
    historytraffic_send_ratio = python_multiprocess/(topo_e*len(topo_SLICENDICT)) #custom
    historytraffic_scale = 0.8 #custom
    edge_bandwidth_scale = 0.8 #custom

    topo_G = nx.Graph()
    hostlist = [i for i in range(topo_h)]
    nodelist = [i for i in range(topo_n)]

    #random edgelist
    edgedict = {(u, v):1 for u in nodelist for v in nodelist if u != v and ((u+1)%topo_n == v or (u-1)%topo_n == v)}
    edgelist=[k for k, v in edgedict.items() if v != 0]

    edgecountdict = copy.deepcopy(edgedict)
    edge_num = 0
    for k,v in edgecountdict.items():
        n1=k[0]
        n2=k[1]
        if v != 0:
            edge_num += 1
            edgecountdict[(n1,n2)]=0
            edgecountdict[(n2,n1)]=0

    topo_G.add_nodes_from(nodelist)
    topo_G.add_edges_from(edgelist)

    #networkx no host, so add host label
    for s in topo_G.nodes():
        topo_G.nodes[s]['host'] = []
    for h in hostlist:
        try:
            topo_G.nodes[h]['host'].append(hostlist[h])
        except:
            print("gg: host > switch")

    #hop so weight is 1
    for u, v in topo_G.edges():
        topo_G[u][v]['weight'] = 1

    ####################check####################
    SLICE_TRAFFIC_MAP = {
        #0chat #1email #2file #3stream #4p2p #5voip #6browser
        0: 0, #0chat
        1: 1, #1email
        2: 5, #5voip
        3: 6, #6browser
        4: 3, #3stream
        5: 2, #2file
        6: 4, #4p2p
    }
    ####################check####################

    ####################check####################
    SLICE_TRAFFIC_NUM = {
        #0chat #1email #2file #3stream #4p2p #5voip #6browser
        0: 6, #0chat
        1: 6, #1email
        2: 0, #5voip
        3: 0, #6browser
        4: 0, #3stream
        5: 0, #2file
        6: 0, #4p2p
    }
    ####################check####################

    SLICE_TRAFFIC_NORMALNUM = __SLICE_TRAFFIC_NORMALNUM(historytraffic_send_ratio, SLICE_TRAFFIC_NUM)


    #MUST CHECK you want avg or median
    INNTER_ARRIVAL_TIME = __INNTER_ARRIVAL_TIME(orig_AVG_INNTER_ARRIVAL_TIME, SLICE_TRAFFIC_MAP)
    #MUST CHECK you want avg or median

    #MUST CHECK you want avg or median
    ONE_PKT_SIZE = __ONE_PKT_SIZE(orig_AVG_ONE_PKT_SIZE, SLICE_TRAFFIC_MAP)
    #MUST CHECK you want avg or median

    #### control result here ###
    ONE_PKT_SIZE[1] = ONE_PKT_SIZE[1] * 1 ###custom
    #### control result here ###

    """
    cal total packets
    """

    #fit interval_lowlimit
    if interval_lowlimit_ctrl == True:
        INNTER_ARRIVAL_TIME = __interval_lowlimit(INNTER_ARRIVAL_TIME)

    NUM_PKT = __NUM_PKT (TOTAL_TIME, INNTER_ARRIVAL_TIME)

    """
    traffic generate
    """

    HISTORYTRAFFIC = {i:{} for i in topo_SLICENDICT.keys()}

    #directed, not edge, host to host
    for i, i_dict in HISTORYTRAFFIC.items():
        HISTORYTRAFFIC[i][(0, 2)] = 0
        HISTORYTRAFFIC[i][(2, 0)] = 0
        HISTORYTRAFFIC[i][(1, 3)] = 0
        HISTORYTRAFFIC[i][(3, 1)] = 0
        HISTORYTRAFFIC[i][(2, 3)] = 0
        HISTORYTRAFFIC[i][(3, 2)] = 0

    #gen and sum traffic
    sum_HISTORYTRAFFIC = 0
    cnt_HISTORYTRAFFIC = 0
    check_TRAFFIC=0
    for i, i_dict in HISTORYTRAFFIC.items():
        pair_list=[]
        traffic_cnt=[]
        # send ratio
        send_list=[e for e in i_dict.keys()]
        if len(send_list) >= SLICE_TRAFFIC_NORMALNUM[i]:
            choice_send_list = random.sample(send_list, SLICE_TRAFFIC_NORMALNUM[i])
        else:
            choice_send_list = send_list
        #dict
        for e in i_dict.keys():
            if e in choice_send_list:
                pair_list.append(e)
                traffic_cnt.append(0)
            scaledict = __gen_scaledict(pair_list, traffic_cnt, historytraffic_scale,shuffle=False)
        #gen
        for p in pair_list:
            v1=p[0]
            v2=p[1]            
            HISTORYTRAFFIC[i][(v1, v2)] = int(\
                ONE_PKT_SIZE[i] * \
                float(1/INNTER_ARRIVAL_TIME[i]) * \
                scaledict[p])

            sum_HISTORYTRAFFIC += HISTORYTRAFFIC[i][(v1, v2)]
            check_TRAFFIC += HISTORYTRAFFIC[i][(v1, v2)]
            cnt_HISTORYTRAFFIC += 1

    if print_ctrl == True:
        pprint.pprint(HISTORYTRAFFIC)
        print(sum_HISTORYTRAFFIC)
        print(cnt_HISTORYTRAFFIC)

    EXTRATRAFFIC = copy.deepcopy(HISTORYTRAFFIC)
    for i, i_dict in EXTRATRAFFIC.items():
        for v1,v2 in i_dict.keys():
            EXTRATRAFFIC[i][(v1, v2)] = 0
            check_TRAFFIC += EXTRATRAFFIC[i][(v1, v2)]

    check_TRAFFIC=check_TRAFFIC*TOTAL_TIME

    """
    cal bandwidth
    """

    if int(sum_HISTORYTRAFFIC/(2**20)) > hw_limit:
        print(f"{sum_HISTORYTRAFFIC/(2**20)}>{hw_limit}")
    else:
        print(f"{sum_HISTORYTRAFFIC/(2**20)}<={hw_limit}")

    if int(cnt_HISTORYTRAFFIC) > python_multiprocess:
        print(f"{cnt_HISTORYTRAFFIC}>{python_multiprocess}")
    else:
        print(f"{cnt_HISTORYTRAFFIC}<={python_multiprocess}")


    EDGE_BANDWIDTH_G = topo_G.copy()
    for v1, v2 in EDGE_BANDWIDTH_G.edges():
        EDGE_BANDWIDTH_G[v1][v2]['weight'] = 0
        EDGE_BANDWIDTH_G[v2][v1]['weight'] = EDGE_BANDWIDTH_G[v1][v2]['weight']

    #shuffle bandwidth
    pair_list=[]
    traffic_cnt=[]
    for v1, v2 in EDGE_BANDWIDTH_G.edges():
        e = (v1, v2)
        pair_list.append(e)
        traffic_cnt.append(0)
    scaledict = __gen_scaledict(pair_list, traffic_cnt, edge_bandwidth_scale,shuffle=True)
    #gen
    avg_b = sum_HISTORYTRAFFIC / edge_num

    EDGE_BANDWIDTH_G[0][1]['weight'] = 12000
    EDGE_BANDWIDTH_G[1][0]['weight'] = EDGE_BANDWIDTH_G[0][1]['weight']
    EDGE_BANDWIDTH_G[0][3]['weight'] = 20000
    EDGE_BANDWIDTH_G[3][0]['weight'] = EDGE_BANDWIDTH_G[0][3]['weight']
    EDGE_BANDWIDTH_G[1][2]['weight'] = 2000
    EDGE_BANDWIDTH_G[2][1]['weight'] = EDGE_BANDWIDTH_G[1][2]['weight']
    EDGE_BANDWIDTH_G[2][3]['weight'] = 20000
    EDGE_BANDWIDTH_G[3][2]['weight'] = EDGE_BANDWIDTH_G[2][3]['weight']

    if print_ctrl == True:
        for v1, v2 in EDGE_BANDWIDTH_G.edges():
            print(f"({v1},{v2}):{EDGE_BANDWIDTH_G[v1][v2]['weight']}")

    #aging
    EST_SLICE_AGING = __EST_SLICE_AGING (TOTAL_TIME)
    EST_SLICE_ONE_PKT =  __EST_SLICE_ONE_PKT (MONITOR_PERIOD, INNTER_ARRIVAL_TIME, ONE_PKT_SIZE)

    MININET_BW = __MININET_BW (EDGE_BANDWIDTH_G)



#custom
#gen graph
elif EXP_TYPE == "two_routing":
    print("two_routing")

    topo_h = 2
    topo_n = 2
    topo_e = (topo_n-1)*topo_n

    #exp var ratio
    edge_min_connect = 1 #custom at least 1 connect
    python_multiprocess = 2 #custom at least 2
    historytraffic_send_ratio = python_multiprocess/(topo_e*len(topo_SLICENDICT)) #custom
    historytraffic_scale = 0.8 #custom
    edge_bandwidth_scale = 0.8 #custom

    topo_G = nx.Graph()
    hostlist = [i for i in range(topo_h)]
    nodelist = [i for i in range(topo_n)]

    #random edgelist
    edgedict = {(u, v):1 for u in nodelist for v in nodelist if u != v and ((u+1)%topo_n == v or (u-1)%topo_n == v)}
    edgelist=[k for k, v in edgedict.items() if v != 0]

    edgecountdict = copy.deepcopy(edgedict)
    edge_num = 0
    for k,v in edgecountdict.items():
        n1=k[0]
        n2=k[1]
        if v != 0:
            edge_num += 1
            edgecountdict[(n1,n2)]=0
            edgecountdict[(n2,n1)]=0

    topo_G.add_nodes_from(nodelist)
    topo_G.add_edges_from(edgelist)

    #networkx no host, so add host label
    for s in topo_G.nodes():
        topo_G.nodes[s]['host'] = []
    for h in hostlist:
        try:
            topo_G.nodes[h]['host'].append(hostlist[h])
        except:
            print("gg: host > switch")

    #hop so weight is 1
    for u, v in topo_G.edges():
        topo_G[u][v]['weight'] = 1

    ####################check####################
    SLICE_TRAFFIC_MAP = {
        #0chat #1email #2file #3stream #4p2p #5voip #6browser
        0: 3, #3stream
        1: 5, #5voip
        2: 0, #0chat
        3: 6, #6browser
        4: 1, #1email
        5: 2, #2file
        6: 4, #4p2p
    }
    ####################check####################

    ####################check####################
    SLICE_TRAFFIC_NUM = {
        #0chat #1email #2file #3stream #4p2p #5voip #6browser
        0: 1, #3stream
        1: 1, #5voip
        2: 0, #0chat
        3: 0, #6browser
        4: 0, #1email
        5: 0, #2file
        6: 0, #4p2p
    }
    ####################check####################

    SLICE_TRAFFIC_NORMALNUM = __SLICE_TRAFFIC_NORMALNUM(historytraffic_send_ratio, SLICE_TRAFFIC_NUM)
    print(SLICE_TRAFFIC_NORMALNUM)

    #MUST CHECK you want avg or median
    INNTER_ARRIVAL_TIME = __INNTER_ARRIVAL_TIME(orig_AVG_INNTER_ARRIVAL_TIME, SLICE_TRAFFIC_MAP)
    #MUST CHECK you want avg or median

    #MUST CHECK you want avg or median
    ONE_PKT_SIZE = __ONE_PKT_SIZE(orig_AVG_ONE_PKT_SIZE, SLICE_TRAFFIC_MAP)
    #MUST CHECK you want avg or median

    #### control result here ###
    ONE_PKT_SIZE[1] = ONE_PKT_SIZE[1]
    #### control result here ###

    """
    cal total packets
    """

    #fit interval_lowlimit
    if interval_lowlimit_ctrl == True:
        INNTER_ARRIVAL_TIME = __interval_lowlimit(INNTER_ARRIVAL_TIME)

    NUM_PKT = __NUM_PKT (TOTAL_TIME, INNTER_ARRIVAL_TIME)

    """
    traffic generate
    """

    HISTORYTRAFFIC = {i:{} for i in topo_SLICENDICT.keys()}

    #directed, not edge, host to host
    for i, i_dict in HISTORYTRAFFIC.items():
        HISTORYTRAFFIC[i][(0, 1)] = 0
        HISTORYTRAFFIC[i][(1, 0)] = 0

    #gen and sum traffic
    sum_HISTORYTRAFFIC = 0
    cnt_HISTORYTRAFFIC = 0
    check_TRAFFIC=0
    for i, i_dict in HISTORYTRAFFIC.items():
        pair_list=[]
        traffic_cnt=[]
        # send ratio
        send_list=[e for e in i_dict.keys()]
        if len(send_list) >= SLICE_TRAFFIC_NORMALNUM[i]:
            choice_send_list = random.sample(send_list, SLICE_TRAFFIC_NORMALNUM[i])
        else:
            choice_send_list = send_list
        #dict
        for e in i_dict.keys():
            if e in choice_send_list:
                pair_list.append(e)
                traffic_cnt.append(0)
            scaledict = __gen_scaledict(pair_list, traffic_cnt, historytraffic_scale,shuffle=False)
        #gen
        for p in pair_list:
            v1=p[0]
            v2=p[1]            
            HISTORYTRAFFIC[i][(v1, v2)] = int((i+1)*11111)

            """
            int(\
                ONE_PKT_SIZE[i] * \
                float(1/INNTER_ARRIVAL_TIME[i]) * \
                scaledict[p])
            """
            sum_HISTORYTRAFFIC += HISTORYTRAFFIC[i][(v1, v2)]
            check_TRAFFIC += HISTORYTRAFFIC[i][(v1, v2)]
            cnt_HISTORYTRAFFIC += 1

    ###if print_ctrl == True:
    pprint.pprint(HISTORYTRAFFIC)
    print(sum_HISTORYTRAFFIC)
    print(cnt_HISTORYTRAFFIC)

    EXTRATRAFFIC = copy.deepcopy(HISTORYTRAFFIC)
    for i, i_dict in EXTRATRAFFIC.items():
        for v1,v2 in i_dict.keys():
            EXTRATRAFFIC[i][(v1, v2)] = 0
            check_TRAFFIC += EXTRATRAFFIC[i][(v1, v2)]

    check_TRAFFIC=check_TRAFFIC*TOTAL_TIME

    """
    cal bandwidth
    """

    if int(sum_HISTORYTRAFFIC/(2**20)) > hw_limit:
        print(f"{sum_HISTORYTRAFFIC/(2**20)}>{hw_limit}")
    else:
        print(f"{sum_HISTORYTRAFFIC/(2**20)}<={hw_limit}")

    if int(cnt_HISTORYTRAFFIC) > python_multiprocess:
        print(f"{cnt_HISTORYTRAFFIC}>{python_multiprocess}")
    else:
        print(f"{cnt_HISTORYTRAFFIC}<={python_multiprocess}")


    EDGE_BANDWIDTH_G = topo_G.copy()
    for v1, v2 in EDGE_BANDWIDTH_G.edges():
        EDGE_BANDWIDTH_G[v1][v2]['weight'] = 0
        EDGE_BANDWIDTH_G[v2][v1]['weight'] = EDGE_BANDWIDTH_G[v1][v2]['weight']

    #shuffle bandwidth
    pair_list=[]
    traffic_cnt=[]
    for v1, v2 in EDGE_BANDWIDTH_G.edges():
        e = (v1, v2)
        pair_list.append(e)
        traffic_cnt.append(0)
    scaledict = __gen_scaledict(pair_list, traffic_cnt, edge_bandwidth_scale,shuffle=True)
    #gen
    avg_b = sum_HISTORYTRAFFIC / edge_num

    EDGE_BANDWIDTH_G[0][1]['weight'] = 8*2**20
    EDGE_BANDWIDTH_G[1][0]['weight'] = EDGE_BANDWIDTH_G[0][1]['weight']

    if print_ctrl == True:
        for v1, v2 in EDGE_BANDWIDTH_G.edges():
            print(f"({v1},{v2}):{EDGE_BANDWIDTH_G[v1][v2]['weight']}")

    #aging
    EST_SLICE_AGING = __EST_SLICE_AGING (TOTAL_TIME)
    EST_SLICE_ONE_PKT =  __EST_SLICE_ONE_PKT (MONITOR_PERIOD, INNTER_ARRIVAL_TIME, ONE_PKT_SIZE)

    MININET_BW = __MININET_BW (EDGE_BANDWIDTH_G)
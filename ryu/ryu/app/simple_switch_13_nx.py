# Copyright (C) 2011 Nippon Telegraph and Telephone Corporation.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.


from collections import deque
from ryu.base import app_manager

from ryu.controller import ofp_event
from ryu.controller.handler import CONFIG_DISPATCHER
from ryu.controller.handler import MAIN_DISPATCHER, HANDSHAKE_DISPATCHER, DEAD_DISPATCHER
from ryu.controller.handler import set_ev_cls

from ryu.ofproto import ofproto_v1_3
from ryu.ofproto import ether
from ryu.ofproto import inet

from ryu.lib.packet import packet
from ryu.lib.packet import ethernet
from ryu.lib.packet import ether_types
from ryu.lib.packet import ipv4, ipv6
from ryu.lib.packet import udp, tcp
from ryu.lib.packet import icmp

from ryu.lib import hub
from ryu.lib import ofctl_v1_3
from operator import attrgetter

from ryu.topology.api import get_all_host, get_all_link, get_all_switch

from ryu_customapp import ryu_preprocessing, ryu_scheduler, ryu_slicealgo



#sklearn
from ryu.lib import pcaplib
import joblib
import tempfile

#innerdelay
import os
import time
import netaddr
import csv

import json
import math
import random
import pprint
import copy

import networkx as nx

import sys
sys.path.insert(1, "./")
from exp_config.exp_config import \
ROUTING_TYPE, SCHEDULER_TYPE, EXP_TYPE, RANDOM_SEED_NUM,     \
GOGO_TIME, TOTAL_TIME, MONITOR_PERIOD,     \
EST_SLICE_ONE_PKT ,  EST_SLICE_AGING,    \
DYNBW_TYPE,     \
SLICE_TRAFFIC_MAP,     \
topo_G,     \
topo_SLICENDICT, topo_GNode0_alignto_mininetSwitchNum,     \
HISTORYTRAFFIC, EDGE_BANDWIDTH_G, check_TRAFFIC



from exp_utils.exp_utils import \
G_to_M, M_to_G, num_to_hostmac, hostmac_to_num, num_to_hostipv4, hostipv4_to_num, num_to_switchmac, L4port_to_clienttraffictype

class SimpleSwitch13(app_manager.RyuApp):
    OFP_VERSIONS = [ofproto_v1_3.OFP_VERSION]

    def __init__(self, *args, **kwargs):
        super(SimpleSwitch13, self).__init__(*args, **kwargs)
        self.ofctl = ofctl_v1_3

        self.datapaths = {}

        """
        custom
        """
        #flow table entry timeout
        self.hard_timeout = ryu_scheduler.scheduler_hard_timeout(0,0)
        #["unknown"] = unknown class
        self.hard_timeout["unknown"] = 0

        #print_ctrl, if True then print info
        self.AllPacketInfo_ctrl   = False
        self.SliceDraw_ctrl       = True
        self.EstDraw_ctrl         = False
        self.ClassifierPrint_ctrl = False
        self.ScheudulerPrint_ctrl = False
        self.ActionPrint_ctrl     = False
        self.MonitorPrint_ctrl    = False
        self.LatencyPrint_ctrl    = False
        self.BWRecord_ctrl        = False


        #function_ctrl
        #False (self.Classifier_ctrl,self.Latency_ctrl)
        self.Classifier_ctrl   = False  # False = allright by ip, True = classification by model
        self.Routing_ctrl      = ROUTING_TYPE #bellman-ford, algo
        self.Scheuduler_ctrl   = SCHEDULER_TYPE  # False, "random", "MAX", "min", "algo", "max_flow"
        self.FlowMatch_ctrl    = True
        self.Monitor_ctrl      = True
        self.Latency_ctrl      = False
        self.BWaging_ctrl      = False
        self.DynamicBW_ctrl    = DYNBW_TYPE #"rt_port","est_avg"


        #topology info from mininet
        self.SliceDict = copy.deepcopy(topo_SLICENDICT)
        self.SliceNum = len(self.SliceDict)
        mininetSwitchPortDict = json.load(open("mininetSwitchPortDict.txt"))
        mininetHostSwitchDict = json.load(open("mininetHostSwitchDict.txt"))
        self.ryuSwitchPortDict = {}
        self.ryuHostSwitchDict = {}

        # switch to switch
        # change value type to int if no char 'h'or's'
        self.SwitchOutportDict = {}
        for k,d in mininetSwitchPortDict.items():
            try:
                self.SwitchOutportDict[int(k)] = {}
            except:
                pass

            for s,p in d.items():
                try:
                    self.SwitchOutportDict[int(k)][int(s)] = int(p)
                except:
                    #port is link to host str('h(num)')
                    self.SwitchOutportDict[int(k)][str(s)] = int(p)


        # reverse key,value search port of switch to know go to what switch
        self.OutportSwitchDict = {}
        for k,d in mininetSwitchPortDict.items():
            try:
                self.OutportSwitchDict[int(k)] = {}
            except:
                pass

            for s,p in d.items():
                try:
                    self.OutportSwitchDict[int(k)][int(p)] = int(s)
                except:
                    if s in str(s):
                        self.OutportSwitchDict[int(k)][int(p)] = int(k)

        # host to switch
        #change value type to int if no char 'h'or's'
        self.HostDstsDict = {}
        for h,s in mininetHostSwitchDict.items():
            try:
                self.HostDstsDict[int(h)] = int(s)
            except:
                pass



        #new record csv for this exp
        dir_name = "exp_csvrecord"
        if not os.path.exists(dir_name):
            os.makedirs(dir_name)
        file_name = time.time()
        record_type = str(ROUTING_TYPE) + "_" + str(SCHEDULER_TYPE) + "_" + str(EXP_TYPE) + "_" + str(DYNBW_TYPE)
        self.csv_throughput_record_filepath = "./"+str(dir_name)+"/"+ str(file_name) + "_" + record_type + ".csv"
        self.csv_estBW_record_filepath = "./"+str(dir_name)+"/"+ str(file_name) + "_" + record_type + ".csv"

        with open(self.csv_throughput_record_filepath, "w") as csv_throughput_record_file:

            row = [record_type]
            for csvsrcid,toswitchdict in self.SwitchOutportDict.items():
                for csvportno in toswitchdict.values():
                    if "routing" in EXP_TYPE:
                        if csvportno == 1:
                            row.append(str(csvsrcid)+","+str(csvportno)+","+"Rx")
                            row.append(str(csvsrcid)+","+str(csvportno)+","+"Tx")
                    else:
                        row.append(str(csvsrcid)+","+str(csvportno)+","+"Rx")
                        row.append(str(csvsrcid)+","+str(csvportno)+","+"Tx")

            writer = csv.writer(csv_throughput_record_file)
            writer.writerow(row)
            row = []

            row = [check_TRAFFIC]
            first_col = ord('B')
            first_row = 3
            csv_col_i = 0
            sum_list=[]
            for csvsrcid,toswitchdict in self.SwitchOutportDict.items():
                for csvportno in toswitchdict.values():
                    if "routing" in EXP_TYPE:
                        if csvportno == 1:
                            row.append('=sum('+chr(first_col+csv_col_i)+str(first_row)+':'+chr(first_col+csv_col_i)+str(first_row+TOTAL_TIME)+')')
                            sum_list.append(chr(first_col+csv_col_i)+str(first_row-1))
                            row.append('=sum('+chr(first_col+csv_col_i+1)+str(first_row)+':'+chr(first_col+csv_col_i+1)+str(first_row+TOTAL_TIME)+')')
                            csv_col_i += 2
                    else:
                        row.append('=sum('+chr(first_col+csv_col_i)+str(first_row)+':'+chr(first_col+csv_col_i)+str(first_row+TOTAL_TIME)+')')
                        row.append('=sum('+chr(first_col+csv_col_i+1)+str(first_row)+':'+chr(first_col+csv_col_i+1)+str(first_row+TOTAL_TIME)+')')
                        csv_col_i += 2
            sum_row=''
            for r in sum_list:
                sum_row += str(r)
                if r != sum_list[-1]:
                    sum_row += '+'
            sum_row = '=('+sum_row+')/$A$2'
            row.append(sum_row)
            writer = csv.writer(csv_throughput_record_file)
            writer.writerow(row)
            row = []

        if self.BWRecord_ctrl == True:
            with open(self.csv_estBW_record_filepath, "w") as csv_estBW_record_file:
                row = [GOGO_TIME]
                row.append("select")
                row.append("s-dsts")
                for i in self.SliceDict.keys():
                    s=str(i)
                    row.append(s)
                writer = csv.writer(csv_estBW_record_file)
                writer.writerow(row)
                row = []

        #for classifier
        self.loaded_model = joblib.load(
            "./ryu/ryu/app/ryu_customapp/models/b255v6 RandomForest choice_random=0.004 train_size=0.8 test_size=0.2 choice_split=3 choice_train=2 1630563027.216647.pkl"
        )
        self.packet_count = 0
        self.slice_class_count = {i:{u:{v:0 for v in self.HostDstsDict.keys()} for u in self.HostDstsDict.keys()} for i in self.SliceDict.keys()}
        #["unknown"] = unknown class
        self.slice_class_count["unknown"] = {u:{v:0 for v in self.HostDstsDict.keys()} for u in self.HostDstsDict.keys()}
        self.pcapfile = tempfile.NamedTemporaryFile(delete = False)
        #self.pcap_writer = pcaplib.Writer(open("mypcap.pcap", "wb"), snaplen = 40)
        self.pcap_writer = pcaplib.Writer(open(self.pcapfile.name, "wb"), snaplen = 40)

        #for scheduler
        self.total_length = 0

        #class mapping
        self.app_to_port = {s:{} for s in self.SwitchOutportDict.keys()}
        self.app_to_service = {
            0: 0,
            1: 1,
            2: 6,
            3: 2,
            4: 1,
            5: 5,
            6: 0,
            7: 3,
            8: 2,
            9: 2,
            10: 5,
            11: 3,
            12: 4,
            13: 6,
            14: 3,
            15: 5,
            16: 3,
        }

        self.service_to_string = {
            "unknown": "Unknown",  # no L3 or L4 or error###
            0: "0 Chat",  # 0AIM, 6ICQ
            1: "1 Email",  # 1Email, 4Gmail
            2: "2 File Transfer",  # 3FTPS, 8SCP, 9SFTP
            3: "3 Streaming",  # 7Netflix, 14Vimeo, 16YouTube
            4: "4 P2P",  # 12Torrent
            5: "5 VoIP",  # 5Hangouts, 10Skype, 11Spotify, 15Voipbuster
            6: "6 Browser",  # 2Facebook, 13 Tor
        }

        #mapping SLICE_TRAFFIC_MAP
        for k,v in self.app_to_service.items():
            self.app_to_service[k] = SLICE_TRAFFIC_MAP[v]
        #write new by orignal, so copy temp
        temp_service_to_string = copy.deepcopy(self.service_to_string)
        for k in self.service_to_string.keys():
            if k != "unknown":
                self.service_to_string[k] = temp_service_to_string[SLICE_TRAFFIC_MAP[k]]

        """
        0 AIM        :0 Chat
        1 Email      :1 Email
        2 Facebook   :6 Browser
        3 FTPS       :2 File Transfer
        4 Gmail      :1 Email
        5 Hangouts   :5 VoIP
        6 ICQ        :0 Chat
        7 Netflix    :3 Streaming
        8 SCP        :2 File Transfer
        9 SFTP       :2 File Transfer
        10 Skype     :5 VoIP
        11 Spotify   :5 VoIP
        12 Torrent   :4 P2P
        13 Tor       :6 Browser
        14 Vimeo     :3 Streaming
        15 Voipbuster:5 VoIP
        16 YouTube   :3 Streaming
        """

        #monitor
        self.sleep_period = MONITOR_PERIOD
        if self.Monitor_ctrl == True:
            self.monitor_thread = hub.spawn(self._monitor)

        self.moniter_record = {
            "prev_tx_bytes": {s:{portno:0 for portno in toswitchdict.values()} for s,toswitchdict in self.SwitchOutportDict.items()},
            "prev_rx_bytes": {s:{portno:0 for portno in toswitchdict.values()} for s,toswitchdict in self.SwitchOutportDict.items()},
            "prev_tx_packets": {s:{portno:0 for portno in toswitchdict.values()} for s,toswitchdict in self.SwitchOutportDict.items()},
            "prev_rx_packets": {s:{portno:0 for portno in toswitchdict.values()} for s,toswitchdict in self.SwitchOutportDict.items()},
            "tx_curr": {s:{portno:0 for portno in toswitchdict.values()} for s,toswitchdict in self.SwitchOutportDict.items()},
            "rx_curr": {s:{portno:0 for portno in toswitchdict.values()} for s,toswitchdict in self.SwitchOutportDict.items()},
        }

        for s in self.SwitchOutportDict.keys():
            self.moniter_record["tx_curr"][s][4294967294] = 0
            self.moniter_record["rx_curr"][s][4294967294] = 0

        ###WARING
        #latency
        if self.LatencyPrint_ctrl == True:
            self.latency_thread = hub.spawn(self._latency)

        self.innerdelay = {s:0 for s in self.SwitchOutportDict.keys()}
        self.reqecho_timestamp = {s:0 for s in self.SwitchOutportDict.keys()}

        self.ping_req_timestamp = {u:{v:0 for v in self.SwitchOutportDict.keys()} for u in self.SwitchOutportDict.keys() }
        self.ping_reqin_timestamp = {u:{v:0 for v in self.SwitchOutportDict.keys()} for u in self.SwitchOutportDict.keys() }
        self.ping_rly_timestamp = {u:{v:0 for v in self.SwitchOutportDict.keys()} for u in self.SwitchOutportDict.keys() }
        self.ping_rlyin_timestamp = {u:{v:0 for v in self.SwitchOutportDict.keys()} for u in self.SwitchOutportDict.keys() }

        self.latency = {u:{v:0 for v in self.SwitchOutportDict.keys()} for u in self.SwitchOutportDict.keys() }
        self.flow_dynamic = {}

        #bandwidth
        self.edge_bandwidth = {u:{v:1 for v in self.SwitchOutportDict.keys()} for u in self.SwitchOutportDict.keys() }
        for s,dsts in EDGE_BANDWIDTH_G.edges():
            self.edge_bandwidth[G_to_M(s)][G_to_M(dsts)] = EDGE_BANDWIDTH_G[s][dsts]['weight']
            self.edge_bandwidth[G_to_M(dsts)][G_to_M(s)] = self.edge_bandwidth[G_to_M(s)][G_to_M(dsts)]

        #HISTORYTRAFFIC host trans to switch
        self.history_traffic = {i:{} for i in self.SliceDict.keys()}
        for ik,iv in HISTORYTRAFFIC.items():
            for k,v in iv.items():
                v1=M_to_G(self.HostDstsDict[G_to_M(k[0])])
                v2=M_to_G(self.HostDstsDict[G_to_M(k[1])])
                if v1!= v2:
                    self.history_traffic[ik][(v1,v2)] = int(0)

        for ik,iv in HISTORYTRAFFIC.items():
            for k,v in iv.items():
                v1=M_to_G(self.HostDstsDict[G_to_M(k[0])])
                v2=M_to_G(self.HostDstsDict[G_to_M(k[1])])
                if v1!= v2:
                    self.history_traffic[ik][(v1,v2)] += v

        #slice bandwidth (estimate) for max_flow only
        self.slice_bandfree_G = copy.deepcopy(EDGE_BANDWIDTH_G)

        #slice bandwidth (estimate)
        self.slice_bandfree = {i:{u:{v:1 for v in self.SwitchOutportDict.keys()} for u in self.SwitchOutportDict.keys()} for i in self.SliceDict.keys()}
        for u in self.SwitchOutportDict.keys():
            for v in self.SwitchOutportDict.keys():
                self.slice_bandfree["unknown"] = {u:{v:4294967294}}

        #slice bandwidth (realtime)
        self.edge_realtime_bandfree = {u:{v:1 for v in self.SwitchOutportDict.keys()} for u in self.SwitchOutportDict.keys()}

        self.slice_bandpkt = copy.deepcopy(EST_SLICE_ONE_PKT)
        self.slice_bandpkt["unknown"] = 60

        self.slice_BWaging_interval = copy.deepcopy(EST_SLICE_AGING)
        self.slice_BWaging_dict = {i:{u:{v:deque([0 for t in range(self.slice_BWaging_interval[i])], maxlen = self.slice_BWaging_interval[i]) for v in self.SwitchOutportDict.keys()} for u in self.SwitchOutportDict.keys()} for i in self.SliceDict.keys()}
        self.slice_BWaging_period = 1

        if self.BWaging_ctrl == True:
            self.slice_BWaging_thread = hub.spawn(self._slice_BWaging )

        """
        topology slice
        """
        #send to algo return subG
        try:
            BW_usage, loading_G, self.topo_slice_G = ryu_slicealgo.slice_algo(topo_G, self.SliceNum, EDGE_BANDWIDTH_G, self.history_traffic, self.SliceDraw_ctrl, self.EstDraw_ctrl, ROUTING_TYPE, EXP_TYPE)
        except:
            print("GG: please check slice routing type")


        divide_BW = {i:{u:{v:1 for v in self.SwitchOutportDict.keys()} for u in self.SwitchOutportDict.keys()} for i in self.SliceDict.keys()}
        for i in self.SliceDict.keys():
            for u,v in loading_G.edges():
                sumBW = loading_G[u][v]['weight']
                if sumBW != 0:
                    ratioBW = BW_usage[i][u][v] / sumBW
                else:
                    ratioBW = 0
                divide_BW[i][G_to_M(u)][G_to_M(v)] = self.edge_bandwidth[G_to_M(u)][G_to_M(v)] * ratioBW
                divide_BW[i][G_to_M(v)][G_to_M(u)] = divide_BW[i][G_to_M(u)][G_to_M(v)]


        #sliceG trans to dict {switch:nextswitch}
        self.dst_switch_ish = {i:{ s:{h:s for h in self.HostDstsDict.keys()} for s in self.SwitchOutportDict.keys() } for i in self.SliceDict.keys()}
        for i,subG in enumerate(self.topo_slice_G):
            for s in self.SwitchOutportDict.keys():
                for h,dsts in self.HostDstsDict.items():

                    #cal next switch in slice path
                    sdpath = self._src_to_dst_path(subG = subG, s = s, dsts = dsts)

                    #assign next switch
                    if s == dsts:
                        self.dst_switch_ish[i][s][h] = s
                    elif sdpath == []:
                        print("GG: not spanning tree")
                        self.dst_switch_ish[i][s][h] = s
                    else:
                        self.dst_switch_ish[i][s][h] = sdpath[1]

                    #assign slice bandfree
                    if s == dsts:
                        self.slice_bandfree[i][s][dsts] = 4294967294
                    elif sdpath == []:
                        print("GG: not spanning tree")
                        self.slice_bandfree[i][s][dsts] = 0
                    else:
                        minBW = self._find_minBW(BW = divide_BW[i], p_gen = sdpath)
                        self.slice_bandfree[i][s][dsts] = minBW
                        self.slice_bandfree[i][dsts][s] = self.slice_bandfree[i][s][dsts]

        if self.BWRecord_ctrl == True:
            for s in self.SwitchOutportDict.keys():
                for h,dsts in self.HostDstsDict.items():
                    with open(self.csv_estBW_record_filepath, "a") as csv_estBW_record_file:
                        row = ["time"]
                        row.append("start")
                        row.append(str(s)+"-"+str(dsts))
                        for i in self.SliceDict.keys():
                            row.append(self.slice_bandfree[i][s][dsts])
                        writer = csv.writer(csv_estBW_record_file)
                        writer.writerow(row)

        # edge_to_outport
        self.outport_SrcsDsts = self.edge_to_outport()

        self.outport_lish = {}
        layerid = "mac"
        self.outport_lish[layerid] = self.layer_to_outport(layerid = layerid)
        layerid = "ipv4"
        self.outport_lish[layerid] = self.layer_to_outport(layerid = layerid)

    def _find_minBW(self, BW, p_gen):
        minBW = None
        if len(p_gen) <2:
            print("only one switch, can't _find_minBW")
            return minBW
        for s1,s2 in zip(p_gen[0::1], p_gen[1::1]):
            if minBW == None:
                minBW = int(BW[s1][s2])
            if int(BW[s1][s2]) < minBW:
                minBW = int(BW[s1][s2])
        return minBW



    def _src_to_dst_path(self, subG, s, dsts):
        if s == dsts:
            p_gen = [[M_to_G(s)]]
        else:
            try:
                p_gen = nx.all_shortest_paths( subG, source = M_to_G(s) , target = M_to_G(dsts))
                p_gen = list(p_gen)
            except:
                print("GG: no simple path, may not connect")
                p_gen = []
                return p_gen
        for si,sitem in enumerate(p_gen[0]):
            p_gen[0][si] = G_to_M(sitem)

        return p_gen[0]



    #dpid mapping
    def dpid_to_switchid(self, dpid):
        return dpid

    def switchid_to_dpid(self, sid):
        return sid

    def edge_to_outport(self):
        outport_DirectedEdge = {}
        for s in self.SwitchOutportDict.keys():
            outport_DirectedEdge[s] = { w:{} for w in self.SwitchOutportDict.keys() }
            for dsts in self.SwitchOutportDict.keys():
                if s == dsts:
                    outport_DirectedEdge[s][dsts] = 0
                else:
                    try:
                        outport_DirectedEdge[s][dsts] = int(self.SwitchOutportDict[s][dsts])
                    except:
                        outport_DirectedEdge[s][dsts] = None
        return outport_DirectedEdge

    # edge_to_outport function
    def layer_to_outport(self, layerid):
        layerid = str.lower(layerid)

        outport_ish = {}
        for slice_num in self.SliceDict.keys():
            outport_ish[slice_num] = {}

            for switch_num in self.SwitchOutportDict.keys():
                outport_ish[slice_num][switch_num] = {}

                for host_num, dsts in self.HostDstsDict.items():

                    dst_switch = self.dst_switch_ish[slice_num][switch_num][host_num]
                    if str.lower(layerid) == "mac":
                        #first switch mac 00:00:00:00:00:01
                        host_addr = num_to_hostmac(host_num = host_num)
                    elif str.lower(layerid) == "ipv4":
                        #first host ip 10.0.0.1
                        host_addr = num_to_hostipv4(host_num = host_num)
                    else:
                        print("Interface not define, modify function layer_to_outport")


                    if switch_num == dst_switch:
                        try:
                            outport_ish[slice_num][switch_num][host_addr] = int(self.SwitchOutportDict[switch_num]['h'+str(host_num)])
                        except:
                            outport_ish[slice_num][switch_num][host_addr] = None
                    else:
                        try:
                            outport_ish[slice_num][switch_num][host_addr] = int(self.SwitchOutportDict[switch_num][dst_switch])
                        except:
                            outport_ish[slice_num][switch_num][host_addr] = None

        return outport_ish

    @set_ev_cls(ofp_event.EventOFPSwitchFeatures, CONFIG_DISPATCHER)
    def switch_features_handler(self, ev):
        datapath = ev.msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        match = parser.OFPMatch()
        actions = [parser.OFPActionOutput(ofproto.OFPP_CONTROLLER, ofproto.OFPCML_NO_BUFFER)]
        hard_timeout = 0
        self.add_flow(datapath = datapath,
                      priority = 0,
                      match = match,
                      actions = actions,
                      hard_timeout=hard_timeout)

    def add_flow(self, datapath, priority, match, actions, hard_timeout, *buffer_id):
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        inst = [parser.OFPInstructionActions(ofproto.OFPIT_APPLY_ACTIONS, actions)]
        if buffer_id:
            mod = parser.OFPFlowMod(datapath = datapath,
                                    command = datapath.ofproto.OFPFC_ADD,
                                    priority = priority,
                                    buffer_id = buffer_id,
                                    match = match,
                                    instructions = inst,
                                    hard_timeout = hard_timeout
                                    )
        else:
            mod = parser.OFPFlowMod(datapath = datapath,
                                    priority = priority,
                                    match = match,
                                    instructions = inst,
                                    hard_timeout = hard_timeout
                                    )
        datapath.send_msg(mod)

    def _send_package(self, msg, datapath, in_port, actions):
        data = None
        ofproto = datapath.ofproto

        if msg.buffer_id == ofproto.OFP_NO_BUFFER:
            data = msg.data
        out = datapath.ofproto_parser.OFPPacketOut(datapath = datapath,
                                                   buffer_id = msg.buffer_id,
                                                   in_port = in_port,
                                                   actions = actions,
                                                   data = data)
        datapath.send_msg(out)



    def _slice_BWaging(self):
        while True:
            for u in self.SwitchOutportDict.keys():
                for v in self.SwitchOutportDict.keys():
                    for i in self.SliceDict.keys():
                        self.slice_bandfree[i][u][v] += self.slice_BWaging_dict[i][u][v][0]
                        self.slice_bandfree[i][v][u] = self.slice_bandfree[i][u][v]
                        self.slice_BWaging_dict[i][u][v].popleft()
                        self.slice_BWaging_dict[i][v][u].popleft()
                        self.slice_BWaging_dict[i][u][v].append(0)
                        self.slice_BWaging_dict[i][v][u].append(0)
            if self.ScheudulerPrint_ctrl == True:
                for i in self.SliceDict.keys():
                    for u in self.SwitchOutportDict.keys():
                        for v in self.SwitchOutportDict.keys():
                            print(f'{i} {u},{v}', end="")
                            print('%16d' % (self.slice_bandfree[i][u][v]), end="")
                            print("\n")
            hub.sleep(self.sleep_period)


    def _getMaxFlowpath(self, weight_G, tupS_v1, tupS_v2):
        try:
            #flow_value, flow_dict = nx.maximum_flow(weight_G, _s = tupS_v1, _t = tupS_v2, capacity='weight')
            flow_dict = nx.max_flow_min_cost(weight_G, s = tupS_v1, t = tupS_v2, capacity='weight')        
            if flow_dict == None:
                return None        
            spath_list=[[]]
            k=tupS_v1
            spath_list[0].append(k)
            i=0
            maxi=len(flow_dict)
            while k!=tupS_v2 and i<maxi:
                k = max(flow_dict[k], key=flow_dict[k].get, default=None)
                spath_list[0].append(k)
                i += 1
            if spath_list == None:
                return None    
            return spath_list
        except:
            return None

    #different switch to lowload slice
    def _out_port_group(self, out_port, class_result, switchid, dst_host, layerid):        

        #host to id
        if layerid == "ipv4":
            dsts = int(self.HostDstsDict[int(hostipv4_to_num(dst_host))])
        elif layerid == "mac":
            dsts = int(self.HostDstsDict[int(hostmac_to_num(dst_host))])
        else:
            print("GG: unset id")
            return out_port
        

        slice_num = class_result
        if class_result == "unknown":
            return out_port
        elif switchid == dsts:
            return out_port            

        if switchid in self.SwitchOutportDict.keys():
            #get value
            flow = copy.deepcopy(self.slice_class_count[class_result][int(hostipv4_to_num(dst_host))])
            latency = copy.deepcopy(self.latency[switchid])
            #get edge_banfree

            if self.DynamicBW_ctrl == "est_avg":
                bandfree = {i:0 for i in range(self.SliceNum)}
                p_gen = {i:0 for i in range(self.SliceNum)}
                for pi in self.SliceDict.keys():
                    p_gen[pi] = self._src_to_dst_path(subG = copy.deepcopy(self.topo_slice_G[pi]), s = switchid, dsts = dsts)
                    bandfree[pi] = self._find_minBW(BW = self.slice_bandfree[pi], p_gen = p_gen[pi])
            elif self.DynamicBW_ctrl == "rt_port":
                bandfree = {i:0 for i in range(self.SliceNum)}
                p_gen = {i:0 for i in range(self.SliceNum)}
                for pi in self.SliceDict.keys():
                    p_gen[pi] = self._src_to_dst_path(subG = copy.deepcopy(self.topo_slice_G[pi]), s = switchid, dsts = dsts)
                    bandfree[pi] = self._find_minBW(BW = self.edge_realtime_bandfree , p_gen = p_gen[pi])
            else:
                print("GG: self.DynamicBW_ctrl")


            if self.Scheuduler_ctrl == False:
                slice_num = class_result 

            elif self.Scheuduler_ctrl == "max_flow":                
                spath = self._getMaxFlowpath(self.slice_bandfree_G, switchid, dsts)                
                if spath == None:
                    return out_port
                elif len(spath) >1 :
                    slice_num = 0
                    next_s = spath[1]                    
                    out_port = self.SwitchOutportDict[switchid][next_s]
                else:
                    return out_port


            elif bandfree[class_result] > self.slice_bandpkt[class_result]:
                slice_num = class_result                        
            elif self.Scheuduler_ctrl == "random":
                slice_num = ryu_scheduler.random_algo(class_result, latency, bandfree, flow)
                out_port = self.outport_lish[layerid][slice_num][switchid][dst_host]
            elif self.Scheuduler_ctrl == "MAX":
                slice_num = ryu_scheduler.MAX_algo(class_result, latency, bandfree, flow)
                out_port = self.outport_lish[layerid][slice_num][switchid][dst_host]
            elif self.Scheuduler_ctrl == "min":
                slice_num = ryu_scheduler.min_algo(class_result, latency, bandfree, flow)
                out_port = self.outport_lish[layerid][slice_num][switchid][dst_host]
            elif self.Scheuduler_ctrl == "algo":
                slice_num = ryu_scheduler.scheduler_algo(class_result, latency, bandfree, flow)    
                out_port = self.outport_lish[layerid][slice_num][switchid][dst_host]                                        
            
            else:
                print(f'GG: please check self.Scheuduler_ctrl')
                slice_num = class_result
        

        if self.DynamicBW_ctrl == "est_avg":
            if p_gen[slice_num] == []:
                pass
            else:
                # consume each switch slice
                #test
                next_s = self.OutportSwitchDict[switchid][out_port]

                if self.Scheuduler_ctrl == "max_flow":
                    self.slice_bandfree_G[switchid][next_s]['weight'] -= self.slice_bandpkt[class_result]
                    self.slice_bandfree_G[next_s][switchid]['weight'] = self.slice_bandfree_G[switchid][next_s]['weight']
                
                self.slice_bandfree[slice_num][switchid][next_s] -= self.slice_bandpkt[class_result]
                self.slice_bandfree[slice_num][next_s][switchid] = self.slice_bandfree[slice_num][switchid][next_s]

                # aging flow in slice
                self.slice_BWaging_dict[slice_num][switchid][next_s][-1] += self.slice_bandpkt[class_result]
                self.slice_BWaging_dict[slice_num][next_s][switchid][-1] = self.slice_BWaging_dict[slice_num][switchid][next_s][-1]
        elif self.DynamicBW_ctrl == "rt_port":
            pass
        else:
            print("GG: self.DynamicBW_ctrl")

        if self.BWRecord_ctrl == True:
            csvtime = time.time()
            bandfree = {i:0 for i in range(self.SliceNum)}
            for pi in self.SliceDict.keys():
                p_gen[pi] = self._src_to_dst_path(subG = copy.deepcopy(self.topo_slice_G[pi]), s = switchid, dsts = dsts)
                bandfree[pi] = self._find_minBW(BW = self.slice_bandfree[pi], p_gen = p_gen[pi])
            with open(self.csv_estBW_record_filepath, "a") as csv_estBW_record_file:
                row=[time.time()]
                row.append(str(class_result)+"/"+str(slice_num)+":"+str(self.slice_bandpkt[class_result]))
                row.append(str(switchid)+"-"+str(dsts))
                for i,v in bandfree.items():
                    row.append(str(v))
                writer = csv.writer(csv_estBW_record_file)
                writer.writerow(row)

        return out_port
    

    @set_ev_cls(ofp_event.EventOFPPacketIn, MAIN_DISPATCHER)
    def _packet_in_handler(self, ev):
        # If you hit this you might want to increase
        # the "miss_send_length" of your switch
        if ev.msg.msg_len < ev.msg.total_len:
            self.logger.debug("packet truncated: only {} of {} bytes",
                              ev.msg.msg_len, ev.msg.total_len)
        msg = ev.msg
        datapath = msg.datapath
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser
        in_port = msg.match["in_port"]
        dpid = datapath.id
        switchid = self.dpid_to_switchid(dpid)
        pkt = packet.Packet(msg.data)

        #need L3 L4 to classifier, if not, will valueerror
        L3_ctrl = False
        L4_ctrl = False
        ICMP_ctrl = False

        try:
            id_eth = pkt.get_protocols(ethernet.ethernet)[0]
            eth_dst = id_eth.dst
            eth_src = id_eth.src
        except:
            eth_dst = "ff:ff:ff:ff:ff:ff"
            eth_src = "ff:ff:ff:ff:ff:ff"

        while L3_ctrl == False:
            try:
                id_ipv6 = pkt.get_protocols(ipv6.ipv6)[0]
                ipv6_dst = id_ipv6.dst
                ipv6_src = id_ipv6.src
                #for scheduler
                self.total_length = id_ipv6.total_length
                ip_dst = ipv6_dst
                ip_src = ipv6_src
                #for classifier
                L3_ctrl = True
                break
            except:
                ipv6_dst = "0:0:0:0:0:0:0:0"
                ipv6_src = "0:0:0:0:0:0:0:0"
                ip_dst = ipv6_dst
                ip_src = ipv6_src
            try:
                id_ipv4 = pkt.get_protocols(ipv4.ipv4)[0]
                ipv4_dst = id_ipv4.dst
                ipv4_src = id_ipv4.src
                #for scheduler
                self.total_length = id_ipv4.total_length
                ip_dst = ipv4_dst
                ip_src = ipv4_src
                arp_dst = ipv4_dst
                arp_src = ipv4_src

                #L4 protocol for mapping
                ip_proto = id_ipv4.proto

                #for classifier
                L3_ctrl = True
                break
            except:
                ipv4_dst = "0.0.0.0"
                ipv4_src = "0.0.0.0"
                ip_dst = ipv4_dst
                ip_src = ipv4_src
                arp_dst = ipv4_dst
                arp_src = ipv4_src
            break

        while L4_ctrl == False:
            try:
                id_tcp = pkt.get_protocols(tcp.tcp)[0]
                tcp_src = id_tcp.src_port
                tcp_dst = id_tcp.dst_port
                #for scheduler
                src_port = tcp_src
                dst_port = tcp_dst
                #for classifier
                L4_ctrl = True
                break
            except:
                tcp_src = 0
                tcp_dst = 0
                src_port = tcp_src
                dst_port = tcp_dst
            try:
                id_udp = pkt.get_protocols(udp.udp)[0]
                udp_src = id_udp.src_port
                udp_dst = id_udp.dst_port
                #for schedulerICMP_ctrl
                L4_ctrl = True
                break
            except:
                udp_src = 0
                udp_dst = 0
                src_port = udp_src
                dst_port = udp_dst
            break

        while ICMP_ctrl == False:
            try:
                id_icmp = pkt.get_protocols(icmp.icmp)[0]
                icmpv4_type = id_icmp.type
                ICMP_ctrl = True
                break
            except:
                ICMP_ctrl = False
                pass
            break

        self.packet_count += 1
        if self.AllPacketInfo_ctrl == True and ipv4_dst != "0.0.0.0" and ipv4_src != "0.0.0.0":
            self.logger.info("---------------------------------------------------------------------------------------")
            self.logger.info("Count switch in_port eth_src           eth_dst           ip_src         ip_dst")
            self.logger.info(f"{self.packet_count:>5} {switchid:>6} {in_port:>7} {eth_src:>17} {eth_dst:>17} {ip_src:<8} {src_port:>5} {ip_dst:<8} {dst_port:>5}")

        #get ping
        request_id = None
        reply_id = None
        if self.Latency_ctrl == True:
            try:
                id_icmp = pkt.get_protocols(icmp.icmp)[0]
                if id_icmp.type == icmp.ICMP_ECHO_REQUEST:
                    if dpid:
                        request_id = id_icmp.data.id
                        self.ping_reqin_timestamp[request_id][dpid] = time.time()

                        #reply
                        echo = id_icmp.data
                        echo.data = bytearray(echo.data)
                        data = self._ping_reply(src_dpid = request_id, dst_dpid = dpid, echo = echo)
                        self._send_ping(src_dpid = request_id, dst_dpid = dpid, data = data)
                        self.ping_rly_timestamp[request_id][dpid] = time.time()

                        innerdelay = self.innerdelay[dpid] + self.innerdelay[request_id]

                        req = self.ping_req_timestamp[request_id][dpid]
                        reqin = self.ping_reqin_timestamp[request_id][dpid]
                        latency_req = reqin - req - innerdelay
                        self.latency[request_id][dpid] = latency_req

                        #for classifier
                        ICMP_ctrl = False

                elif id_icmp.type == icmp.ICMP_ECHO_REPLY:
                    reply_id = id_icmp.data.id
                    self.ping_rlyin_timestamp[dpid][reply_id] = time.time()

                    innerdelay = self.innerdelay[dpid] + self.innerdelay[reply_id]

                    rly = self.ping_rly_timestamp[dpid][reply_id]
                    rlyin = self.ping_rlyin_timestamp[dpid][reply_id]
                    latency_rly = rlyin - rly - innerdelay
                    self.latency[dpid][reply_id] = latency_rly

                    #for classifier
                    ICMP_ctrl = False

                    if self.LatencyPrint_ctrl == True:
                        avg = (self.latency[dpid][reply_id] +
                           self.latency[reply_id][dpid]) / 2

                        loadbar = str("")
                        for i in range(int(avg) * 5):
                            loadbar = loadbar + "■"
                        self.logger.info("---------------------------------------------------------------------------------------")
                        self.logger.info(f"{dpid:<2}-{reply_id:<2} avg latency   request    reply     ")
                        fstringpad = ""
                        self.logger.info(f"{fstringpad:5} {avg:<4.3f} {loadbar:<12} {self.latency[reply_id][dpid]:<10.3f} {self.latency[dpid][reply_id]:<10.3f}")
                    #clean for next time use
                    self.ping_req_timestamp[dpid][reply_id] = 0
                    self.ping_reqin_timestamp[dpid][reply_id] = 0
                    self.ping_rly_timestamp[dpid][reply_id] = 0
                    self.ping_rlyin_timestamp[dpid][reply_id] = 0
            except:
                pass

        #preprocess
        ###open("mypcap.pcap", "wb").close()
        self.pcapfile.flush()
        self.pcap_writer = pcaplib.Writer(open(self.pcapfile.name, "wb"), snaplen = 40)
        self.pcap_writer.write_pkt(ev.msg.data)
        X_test = ryu_preprocessing.transform_pcap(self.pcapfile.name)

        #classifier
        class_result = "unknown"
        if L3_ctrl == True and L4_ctrl == True and ICMP_ctrl == False:
            try:
                #for classifier
                if self.Classifier_ctrl == True:
                    #model return result is list
                    app_result = self.loaded_model.predict(X_test)
                    app_result = int(app_result[0])
                    class_result = self.app_to_service[app_result]
                    class_result = SLICE_TRAFFIC_MAP[class_result]
                else:
                    try:
                        if udp_src:
                            class_result = L4port_to_clienttraffictype(udp_dst)
                        elif tcp_src:
                            class_result = L4port_to_clienttraffictype(tcp_dst)
                    except:
                        #print("unknown class _ctrl")
                        class_result = "unknown"
            except:
                #print("unknown class _ctrl")
                class_result = "unknown"

            #for scheduler
            #check already comes
            src_h = int(hostipv4_to_num(ipv4_src))
            dst_h = int(hostipv4_to_num(ipv4_dst))

            try:
                self.slice_class_count[class_result][src_h][dst_h] += 1
            except:
                print(f"GG: {class_result} L3 switch {src_h}-{dst_h}")
                pass

            if self.ClassifierPrint_ctrl == True:
                print(f"class = {class_result} {self.service_to_string[class_result]} \t {src_h}, {dst_h} \t count = {self.slice_class_count[class_result][src_h][dst_h]}")


        #avoid mistake for next time classifier
        L3_ctrl = False
        L4_ctrl = False
        ICMP_ctrl = False



        #mapping dict_to_port dst src
        #flow table
        if class_result == "unknown":
            hard_timeout = self.hard_timeout[class_result]
            class_result = abs(int(hostipv4_to_num(ipv4_dst) - 1)) % self.SliceNum
            if switchid in self.outport_lish["ipv4"][class_result] and ipv4_dst in self.outport_lish["ipv4"][class_result][switchid]:
                #out_port
                out_port = self.outport_lish["ipv4"][class_result][switchid][ipv4_dst]
                out_port = self._out_port_group(out_port = out_port, class_result = class_result, switchid = switchid, dst_host = ipv4_dst, layerid = "ipv4")
                if self.ActionPrint_ctrl == True:
                    self.logger.info(f"unknown iam s{switchid:<2}(out = {out_port:>2}) dst {ipv4_dst}")
                match = datapath.ofproto_parser.OFPMatch(eth_type = 0x0800, ipv4_dst = ipv4_dst)
                actions = [datapath.ofproto_parser.OFPActionOutput(port = out_port)]
                self.add_flow(datapath = datapath,
                            priority = 10,
                            match = match,
                            actions = actions,
                            hard_timeout = hard_timeout
                            )
                self._send_package(msg, datapath, in_port, actions)
        elif switchid in self.outport_lish["ipv4"][class_result] and ipv4_dst in self.outport_lish["ipv4"][class_result][switchid]:
            
            hard_timeout = self.hard_timeout[class_result]
            #out_port
            out_port = self.outport_lish["ipv4"][class_result][switchid][ipv4_dst]
            out_port = self._out_port_group(out_port = out_port, class_result = class_result, switchid = switchid, dst_host = ipv4_dst, layerid = "ipv4")
            if self.ActionPrint_ctrl == True:
                self.logger.info(f"class{class_result} iam s{switchid:<2}(out = {out_port:>2}) dst {ipv4_dst}")
            #match
            if self.FlowMatch_ctrl == True:
                if tcp_dst:
                    match = datapath.ofproto_parser.OFPMatch(eth_type = 0x0800,
                                                             ipv4_dst = ipv4_dst,
                                                             ip_proto = ip_proto,
                                                             tcp_src = tcp_src,
                                                             tcp_dst = tcp_dst)
                elif udp_dst:
                    match = datapath.ofproto_parser.OFPMatch(eth_type = 0x0800,
                                                             ipv4_dst = ipv4_dst,
                                                             ip_proto = ip_proto,
                                                             udp_src = udp_src,
                                                             udp_dst = udp_dst)
                else:
                    match = datapath.ofproto_parser.OFPMatch(eth_type = 0x0800,
                                                             ipv4_dst = ipv4_dst)
            else:
                match = datapath.ofproto_parser.OFPMatch(eth_type = 0x0800,
                                                         ipv4_dst = ipv4_dst)

            actions = [datapath.ofproto_parser.OFPActionOutput(port = out_port)]
            self.add_flow(datapath = datapath,
                          priority = 0,
                          match = match,
                          actions = actions,
                          hard_timeout = hard_timeout)
            self._send_package(msg, datapath, in_port, actions)
        elif switchid in self.outport_lish["mac"][class_result] and eth_dst in self.outport_lish["mac"][class_result][switchid]:
            hard_timeout = self.hard_timeout[class_result]
            out_port = self.outport_lish["mac"][class_result][switchid][eth_dst]
            out_port = self._out_port_group(out_port = out_port, class_result = class_result, switchid = switchid, dst_host = eth_dst, layerid = "mac")
            if self.ActionPrint_ctrl == True:
                self.logger.info(f"class{class_result} iam s{switchid:<2}(out = {out_port:>2}) dst {eth_dst}")
            match = datapath.ofproto_parser.OFPMatch(eth_dst = eth_dst)
            actions = [datapath.ofproto_parser.OFPActionOutput(port = out_port)]
            self.add_flow(datapath = datapath,
                          priority = 0,
                          match = match,
                          actions = actions,
                          hard_timeout = hard_timeout)
            self._send_package(msg, datapath, in_port, actions)


    #latency

    #  -controller-
    #  |          |
    #  D1         D2
    #  |          |
    #  S1-latency-S3

    #echo = controller -> Sa;Sb -> controller
    #innerdelay D1;D2 = echo /2
    #ping = Controller -> Sa -> Sb -> Controller
    #latency = ping - D1 - D2
    def _latency(self):
        while True:
            for dpid, datapath in self.datapaths.items():
                #for innerdelay
                self._echo_request(datapath)

                #for latency
                for dsts in self.SwitchOutportDict.keys():
                    echo = icmp.echo(id_ = dpid, seq = 1)
                    data = self._ping_request(src_dpid = dpid, dst_dpid = dsts, echo = echo)
                    self._send_ping(src_dpid = dpid, dst_dpid = dsts, data = data)
                    self.ping_req_timestamp[dpid] = time.time()

            hub.sleep(self.sleep_period)

    #innerdelay request
    def _echo_request(self, datapath):
        ofp_parser = datapath.ofproto_parser
        dpid = datapath.id
        req = ofp_parser.OFPEchoRequest(datapath)
        datapath.send_msg(req)
        self.reqecho_timestamp[dpid] = time.time()

    #innerdelay end
    @set_ev_cls(ofp_event.EventOFPEchoReply, [HANDSHAKE_DISPATCHER, CONFIG_DISPATCHER, MAIN_DISPATCHER])
    def _echo_reply_handler(self, ev):
        timestamp_reply = time.time()
        dpid = ev.msg.datapath.id
        self.innerdelay[dpid] = timestamp_reply - self.reqecho_timestamp[dpid]

    #ping
    def _build_ping(self, src_dpid, dst_dpid, _type, echo):
        if _type == icmp.ICMP_ECHO_REQUEST:
            src_switch = src_dpid
            dst_switch = dst_dpid
        elif _type == icmp.ICMP_ECHO_REPLY:
            src_switch = dst_dpid
            dst_switch = src_dpid
        ###WARING
        #flow table no switch addr
        src_port = self.outport_SrcsDsts[src_switch][dst_switch]
        dst_port = self.outport_SrcsDsts[dst_switch][src_switch]
        ###str(self.datapaths[dst_switch].ports[dst_port].hw_addr)
        ###str(self.datapaths[src_switch].ports[dst_port].hw_addr)
        eth_src = num_to_switchmac(src_switch)
        eth_dst = num_to_switchmac(dst_switch)
        ip_src = int(netaddr.IPAddress("0.0.0.0"))
        ip_dst = int(netaddr.IPAddress("0.0.0.0"))
        e = ethernet.ethernet(dst = eth_src,
                              src = eth_dst,
                              ethertype = ether.ETH_TYPE_IP)
        ip = ipv4.ipv4(version = 4,
                       header_length = 5,
                       tos = 0,
                       total_length = 84,
                       identification = 0,
                       flags = 0,
                       offset = 0,
                       ttl = 64,
                       proto = inet.IPPROTO_ICMP,
                       csum = 0,
                       src = ip_src,
                       dst = ip_dst)
        i = icmp.icmp(type_ = _type, code = 0, csum = 0, data = echo)
        p = packet.Packet()
        p.add_protocol(e)
        p.add_protocol(ip)
        p.add_protocol(i)
        p.serialize()
        return p

    def _send_ping(self, src_dpid, dst_dpid, data):
        datapath = self.datapaths[src_dpid]
        out_port = self.outport_SrcsDsts[src_dpid][dst_dpid]
        buffer_id = 0xffffffff
        in_port = datapath.ofproto.OFPP_CONTROLLER
        actions = [datapath.ofproto_parser.OFPActionOutput(port = out_port, max_len = 0)]
        msg = datapath.ofproto_parser.OFPPacketOut(datapath = datapath,
                                                   buffer_id = buffer_id,
                                                   in_port = in_port,
                                                   actions = actions,
                                                   data = data)
        datapath.send_msg(msg)

    def _ping_request(self, src_dpid, dst_dpid, echo):
        p = self._build_ping(src_dpid, dst_dpid, icmp.ICMP_ECHO_REQUEST, echo)
        return p.data

    def _ping_reply(self, src_dpid, dst_dpid, echo):
        p = self._build_ping(src_dpid, dst_dpid, icmp.ICMP_ECHO_REPLY, echo)
        return p.data



    #monitor
    def _request_stats(self, datapath):
        self.logger.debug("send stats request: %016x", datapath.id)
        ofproto = datapath.ofproto
        parser = datapath.ofproto_parser

        req = parser.OFPFlowStatsRequest(datapath)
        datapath.send_msg(req)

        req = parser.OFPPortStatsRequest(datapath, 0, ofproto.OFPP_ANY)
        datapath.send_msg(req)

    def _monitor(self):
        while True:
            for dpid, datapath in self.datapaths.items():
                self._request_stats(datapath)
            hub.sleep(self.sleep_period)

    @set_ev_cls(ofp_event.EventOFPStateChange, [MAIN_DISPATCHER, DEAD_DISPATCHER])
    def _state_change_handler(self, ev):
        datapath = ev.datapath
        if ev.state == MAIN_DISPATCHER:
            if datapath.id not in self.datapaths:
                self.logger.debug("register datapath: %016x", datapath.id)
                self.datapaths[datapath.id] = datapath
        elif ev.state == DEAD_DISPATCHER:
            if datapath.id in self.datapaths:
                self.logger.debug("unregister datapath: %016x", datapath.id)
                del self.datapaths[datapath.id]

    @set_ev_cls(ofp_event.EventOFPPortStatsReply, MAIN_DISPATCHER)
    def _port_stats_reply_handler(self, ev):
        body = ev.msg.body
        dpid = ev.msg.datapath.id

        #monitor slice update
        if dpid:
            for stat in sorted(body, key = attrgetter("port_no")):
                #first pot = port 1
                if stat.port_no < (len(self.OutportSwitchDict[dpid])+1):
                    portno = stat.port_no

                    rx_bytes = stat.rx_bytes - self.moniter_record["prev_rx_bytes"][dpid][portno]
                    self.moniter_record["prev_rx_bytes"][dpid][portno] = stat.rx_bytes
                    self.moniter_record["rx_curr"][dpid][portno] = rx_bytes

                    tx_bytes = stat.tx_bytes - self.moniter_record["prev_tx_bytes"][dpid][portno]
                    self.moniter_record["prev_tx_bytes"][dpid][portno] = stat.tx_bytes
                    self.moniter_record["tx_curr"][dpid][portno] = tx_bytes

                    if self.DynamicBW_ctrl == "rt_port":
                        dsts = self.OutportSwitchDict[dpid][stat.port_no]
                        bandload = self.moniter_record["rx_curr"][dpid][portno] + self.moniter_record["tx_curr"][dpid][portno]
                        self.edge_realtime_bandfree[dpid][dsts] = self.edge_bandwidth[dpid][dsts] - bandload

        #monitor record csv file
        csvtime = time.time()
        if dpid == 1 and csvtime >= GOGO_TIME and csvtime <= GOGO_TIME + TOTAL_TIME:
            with open(self.csv_throughput_record_filepath, "a") as csv_throughput_record_file:
                row = [csvtime]
                for csvsrcid,toswitchdict in self.SwitchOutportDict.items():
                    for csvportno in toswitchdict.values():
                        if "routing" in EXP_TYPE:
                            if csvportno == 1:
                                row.append(self.moniter_record["rx_curr"][csvsrcid][csvportno])
                                row.append(self.moniter_record["tx_curr"][csvsrcid][csvportno])
                        else:
                            row.append(self.moniter_record["rx_curr"][csvsrcid][csvportno])
                            row.append(self.moniter_record["tx_curr"][csvsrcid][csvportno])
                        self.moniter_record["rx_curr"][csvsrcid][csvportno]=0
                        self.moniter_record["tx_curr"][csvsrcid][csvportno]=0
                writer = csv.writer(csv_throughput_record_file)
                writer.writerow(row)

        #monitor pkts bytes
        if self.MonitorPrint_ctrl == True:
            if dpid:
                self.logger.info("datapath         port     "
                                "rx-pkts  rx-bytes rx-curr  "
                                "tx-pkts  tx-bytes tx-curr  "
                                "latency  rt.free  rt.load")
                self.logger.info("---------------- -------- "
                                "-------- -------- -------- "
                                "-------- -------- -------- "
                                "-------- -------- -------- ")

                for stat in sorted(body, key = attrgetter("port_no")):
                    if dpid in self.SwitchOutportDict.keys():
                        if stat.port_no < (len(self.OutportSwitchDict[dpid])+1):
                            dstdpid = self.OutportSwitchDict[dpid][stat.port_no]
                            portno = stat.port_no
                            latency = self.latency[dpid][dstdpid]
                            bandwidth = self.edge_bandwidth[dpid][dstdpid]
                            bandload = self.moniter_record["rx_curr"][dpid][portno] + self.moniter_record["tx_curr"][dpid][portno]
                            bandfree = bandwidth - bandload
                        else:
                            portno = 4294967294
                            latency = 123.567
                            bandwidth = 1
                            bandload = 1
                            bandfree = 1
                    bar = str("")
                    barlen = int(bandload / bandwidth * 11)
                    if barlen > 11:
                        barlen = 11
                    bar = "#"*barlen

                    self.logger.info(
                        "%016x %8x %8d %8d %8d %8d %8d %8d %8.3f %8d %8d %s",
                        ev.msg.datapath.id, stat.port_no,
                        stat.rx_packets, stat.rx_bytes, self.moniter_record["rx_curr"][dpid][portno],
                        stat.tx_packets, stat.tx_bytes, self.moniter_record["tx_curr"][dpid][portno],
                        latency, bandfree, bandload, bar)
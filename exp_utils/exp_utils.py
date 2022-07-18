
import math

import sys
sys.path.insert(1, "./")
from exp_config.exp_config import \
topo_GNode0_alignto_mininetSwitchNum



"""
function
"""
def G_to_M(GNodeNum):
        return GNodeNum + topo_GNode0_alignto_mininetSwitchNum

def M_to_G(SwitchNum):
    return SwitchNum - topo_GNode0_alignto_mininetSwitchNum

def num_to_hostmac(host_num):
    host_num=str(hex(host_num)).lstrip("0x")

    macform=["00"]*6
    leftist_col=math.ceil(len(host_num)/2)
    if len(host_num)%2 == 1:
        leftist_num=host_num[0]
        leftist_num=leftist_num.zfill(2)
        macform[-1*leftist_col]=str(leftist_num)

    i = 1
    for stri,strj in zip(host_num[-2::-2],host_num[-1::-2]):
        strm=stri+strj
        macform[-1*i]=str(strm)
        if i>leftist_col:
            break
        else:
            i += 1

    host_mac_addr=""
    for i in range(6):
        if i == (6-1):
            host_mac_addr = host_mac_addr+macform[i]
        else:
            host_mac_addr = host_mac_addr+macform[i]+":"
    return host_mac_addr

def hostmac_to_num(hostmac):
    return int(str(hostmac).replace(":",""),16)

def num_to_hostipv4(host_num):
    if host_num >= 16777216:
        print("too many host ipv4 gg")

    ipv4form = [10,0,0,0]
    for i in range(1,4):
        ipv4form[-1*i]=int(host_num % 256)
        host_num=int(host_num // 256)

    host_ipv4_addr=""
    for i in range(4):
        if i == (4-1):
            host_ipv4_addr = host_ipv4_addr+str(ipv4form[i])
        else:
            host_ipv4_addr = host_ipv4_addr+str(ipv4form[i])+"."
    return host_ipv4_addr

def hostipv4_to_num(host_ipv4_addr):
    #10.0.0.1 => 1
    ipv4form = [10,0,0,0]
    host_ipv4_addr = host_ipv4_addr.split(".")
    host_ipv4_addr = [int(host_ipv4_addr[i]) - int(ipv4form[i]) for i in range(len(ipv4form))]
    host_num = 0
    for i in range(3):
        host_num = host_num + int(host_ipv4_addr[i] * 256)
    host_num=host_num+ host_ipv4_addr[-1]

    if host_num >= 16777216:
        print("too many host ipv4 gg")

    return host_num 

def num_to_switchmac(switch_num):
    switch_num=str(hex(switch_num)).lstrip("0x")

    macform=["33","33","00","00","00","00"]
    leftist_col=math.ceil(len(switch_num)/2)
    if len(switch_num)%2 == 1:
        leftist_num=switch_num[0]
        leftist_num=leftist_num.zfill(2)
        macform[-1*leftist_col]=str(leftist_num)

    i = 1
    for stri,strj in zip(switch_num[-2::-2],switch_num[-1::-2]):
        strm=stri+strj
        macform[-1*i]=str(strm)
        if i>leftist_col:
            break
        else:
            i += 1

    switch_mac_addr=""
    for i in range(6):
        if i == (6-1):
            switch_mac_addr = switch_mac_addr+macform[i]
        else:
            switch_mac_addr = switch_mac_addr+macform[i]+":"
    return switch_mac_addr

def clienttraffictype_to_L4port(traffictype,client):
    L4port=traffictype*10000+client*100
    return L4port

def L4port_to_clienttraffictype(L4port):
    L4port=str(L4port).zfill(5)
    traffictype=L4port[0]
    return traffictype
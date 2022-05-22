#sudo python3 mininet/custom/custom_example_nxtomini.py
#http://mininet.org/api/annotated.html


from mininet.net import Mininet
from mininet.node import RemoteController
from mininet.link import TCLink
from mininet.cli import CLI
from mininet.clean import Cleanup
from mininet.log import setLogLevel, info, error
from mininet.util import dumpNodeConnections

import networkx as nx
import json
import pprint
import time

from multiprocessing import Process
from subprocess import Popen

import sys
sys.path.insert(1, "./")
from exp_config.exp_config import \
EXP_TYPE,     \
MININET_BW,     \
topo_G,     \
topo_GNode0_alignto_mininetSwitchNum

from exp_utils.exp_utils import \
G_to_M, M_to_G


def topo_G_to_topo_mininet(topo_G):
    topo_mininet = nx.Graph()
    nodelist = []
    edgelist = []
    for s in topo_G.nodes():
        nodelist.append(G_to_M(s))

    for v1,v2 in topo_G.edges():
        edgelist.append((G_to_M(v1),G_to_M(v2)))

    topo_mininet.add_nodes_from(nodelist)
    topo_mininet.add_edges_from(edgelist)

    for s in topo_G.nodes():
        topo_mininet.nodes[G_to_M(s)]['host'] = [G_to_M(h) for h in topo_G.nodes[s]['host']]
    
    return topo_mininet

def MININET_BW_to_bw_mininet(MININET_BW):
    bw_mininet = {}
    for k,v in MININET_BW.items():
        v1 = k[0]
        v2 = k[1]
        bw_mininet[(G_to_M(v1),G_to_M(v2))] = v
    return bw_mininet

def getdictHostConnections ( nodes ):
    nDict = {}
    #"Dump connections to/from nodes."
    def getConnections( node ):
        #"Helper function: dump connections to node"
        for intf in node.intfList():
            if intf.link:
                intfs = [ intf.link.intf1, intf.link.intf2 ]
                intfs.remove( intf )
                sHost = str(intfs[0])
                sHost = sHost.split("-")[0].lstrip("s")
        return sHost

    for node in nodes:
        nodenum=str(node).lstrip("h")
        nDict[nodenum] = getConnections( node )
    
    return nDict

def getdictSwitchConnections ( nodes ):
    nDict = {}
    #"Dump connections to/from nodes."
    def getConnections( node ):
        sDict = {}
        #"Helper function: dump connections to node"
        for intf in node.intfList():
            if intf.link:
                intfs = [ intf.link.intf1, intf.link.intf2 ]
                intfs.remove( intf )
                sPort = str(intf)
                sPort = sPort.split("-eth")[1]
                sHost = str(intfs[0])
                sHost = sHost.split("-")[0].lstrip("s")
                sDict[sHost] = sPort

        return sDict

    for node in nodes:
        nodenum = str(node).lstrip("s")
        nDict[nodenum] = getConnections( node )
    
    return nDict



def myNetwork():
    Cleanup.cleanup()

    topo_mininet = topo_G_to_topo_mininet(topo_G)
    bw_mininet = MININET_BW_to_bw_mininet(MININET_BW)
    
    net = Mininet(
        topo = None,
        autoSetMacs = True,
        autoStaticArp = True,
        build = False)

    info("\n*** Add controller\n")        
    net.addController("c0", controller = RemoteController, ip = "127.0.0.1", port = 6633)  

    info("\n*** Add switches\n")
    SwitchDict = {}
    SwitchNum = {}
    for s in topo_mininet.nodes():
        SwitchNum[s] = "s"+str(s)
        SwitchDict[s] = net.addSwitch(SwitchNum[s])

    info("\n*** Add hostes\n")
    HostDict = {}
    HostNum = {}
    for s in topo_mininet.nodes():
        if topo_mininet.nodes[s]['host'] != []:
            for h in topo_mininet.nodes[s]['host']:
                HostNum[h] = "h"+str(h)
                HostDict[h] = net.addHost(HostNum[h])

    info("\n*** Add linkes\n")
    #host link switch
    for s in topo_mininet.nodes():
        if topo_mininet.nodes[s]['host'] != []:
            for h in topo_mininet.nodes[s]['host']:
                net.addLink(HostDict[h], SwitchDict[s])

    #switch link switch
    for v1,v2 in topo_mininet.edges():
        net.addLink(SwitchDict[v1], SwitchDict[v2], cls = TCLink, bw = bw_mininet[(v1,v2)])

    #net.get
    for i in SwitchDict:
        SwitchDict[i] = net.get(SwitchNum[i])

    for i in HostDict:
        HostDict[i] = net.get(HostNum[i])    



    info("\n*** Start Network\n")
    net.start()

    info("\n***Dumping host connections\n")
    dumpNodeConnections(net.hosts)
    mininetHostSwitchDict = getdictHostConnections(net.hosts)
    #pprint.pprint(mininetHostSwitchDict)
    json.dump(mininetHostSwitchDict, open("mininetHostSwitchDict.txt","w"))
    info("\n***Dumping switch connections\n")
    dumpNodeConnections(net.switches)
    mininetSwitchPortDict = getdictSwitchConnections(net.switches)
    json.dump(mininetSwitchPortDict, open("mininetSwitchPortDict.txt","w"))
    #pprint.pprint(mininetSwitchPortDict)
    

    info("\n*** Dump-flows\n")
    for i in SwitchDict:
        SwitchDict[i].cmdPrint("ovs-ofctl dump-flows s"+str(i))

    info("\n*** Start Ryu Controller\n")
    Popen(["xterm","-e", "ryu-manager ./ryu/ryu/app/simple_switch_13_nx.py"])
    #wait Ryu start
    time.sleep(10)

    """
    ###WARNING  must start controller
    info( "\n***Testing ping\n" )
    net.pingAll()
    net.pingAll()

    ###WARNING  must start controller
    info( "\n***Testing bandwidth\n" )            
    for i,ih in HostDict.items():
        for j,jh in HostDict.items():
            if i != j:
                net.iperf([ih,jh],fmt = "-t 1 -f MBytes")
    """

    info("\n***Sending packet\n")
    def hostClient(i,HostDict_i):
        if EXP_TYPE == "scheduling":
            if i < 8:
                HostDict_i.cmdPrint("python3 pktreplay/cs/client"+str(i)+".py")
            else:
                HostDict_i.cmdPrint("python3 pktreplay/cs/server"+str(i)+".py")
        elif EXP_TYPE == "routing" or "test":
            HostDict_i.cmdPrint("python3 pktgen/cs/client"+str(i)+".py")
          

    ClientDict={}
    for i in HostDict:
        ClientDict[i]=Process(target = hostClient, args = (i,HostDict[i]))
    for i in HostDict:
        ClientDict[i].start()
    for i in HostDict:
        ClientDict[i].join()

    



    CLI(net)

    Cleanup.cleanup()


if __name__ == "__main__":
    setLogLevel("info")
    myNetwork()
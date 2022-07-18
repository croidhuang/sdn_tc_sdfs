import networkx as nx
import networkx.algorithms.tree.mst as mst
import networkx.algorithms.operators.binary as op
import matplotlib.pyplot as plt
import matplotlib.colors

import random
import os

import pprint

from exp_utils.exp_utils import G_to_M

def _removeCycle(T, spath):
    #checkCycle
    checkCycle = nx.utils.UnionFind(T.nodes())
    checkCycle.to_sets()
    for v1, v2 in T.edges():
        checkCycle.union(v1,v2)

    #shortcut
    if list(T.edges()) == []:
        #sp
        spath_graph = nx.Graph()
        for v1, v2 in zip(spath[0::1], spath[1::1]):
            spath_graph.add_edge(v1,v2)
        return spath_graph
    T_v1 = spath[0]
    T_v2 = spath[-1]
    if checkCycle[T_v1] == checkCycle[T_v2]:
        Tpath_gen = nx.all_shortest_paths(T, source = T_v1, target = T_v2)
        Tpath_gen = list(Tpath_gen)
        if Tpath_gen == []:
            print("no simple path, may not connect")
        Tpath_gen = Tpath_gen[0]
        return_graph = nx.Graph()
        for v1, v2 in zip(Tpath_gen[0::1], Tpath_gen[1::1]):
            return_graph.add_edge(v1,v2)
        return return_graph

    #check edge in SP in which T
    vi = 0
    lastindex = (len(spath)-1)
    while vi <= (lastindex-1):
        #print(spath)
        #print(f"vi = {vi}")
        v1 = spath[vi]
        v2 = spath[vi+1]
        #cycle happen, 2nd touch same T
        if checkCycle[v1] != checkCycle[v2]:
            for vti in range(lastindex, (vi+1)-1, -1):
                if checkCycle[spath[vti]] == checkCycle[v1]:
                    vi = vti-1
                    break
                if checkCycle[spath[vti]] == checkCycle[v2]:
                    vi = vti-1
                    checkCycle.union(v1,v2)
                    T.add_edge(v1,v2)
                    break
        vi = vi+1

    #check if new SP at T
    T_v1 = spath[0]
    T_v2 = spath[-1]

    #print(T.edges())
    Tpath_gen = nx.all_shortest_paths(T, source = T_v1, target = T_v2)
    if Tpath_gen == []:
        print("no simple path, may not connect")
    Tpath_gen = list(Tpath_gen)
    Tpath_gen = Tpath_gen[0]
    return_graph = nx.Graph()
    for v1, v2 in zip(Tpath_gen[0::1], Tpath_gen[1::1]):
        return_graph.add_edge(v1,v2)

    return return_graph

def _weightG(G, AC):
    for v1, v2 in G.edges():
        G[v1][v2]['weight']=AC[v1][v2]['weight']
        G[v2][v1]['weight']=G[v1][v2]['weight']
    return G

def _noCycle(G):
    A = nx.utils.UnionFind(G.nodes())
    A.to_sets()
    for v1, v2 in G.edges():
        if A[v1] != A[v2]:
            A.union(v1,v2)
        else:
            return False
    return True

    """
    ##tree so could do, if not tree should DFS base function to search
    try:
        nx.find_cycle(G)
        return False
    except nx.exception.NetworkXNoCycle:
        return True
    """

def _isConnected(T):
    if len(T.edges())==len(T.nodes())-1:
        return True
    else:
        return False

def _addPath(G, spath_G):
    for v1, v2 in spath_G.edges():
        G.add_edge(v1,v2)
    return G

def _unionEdge(v1, v2, topo_sliceG_i, loading_G, EDGE_BANDWIDTH_G, BW_usage_i, used_Edge_i , trafficE, allo_G):
    topo_sliceG_i.add_edge(v1,v2)

    loading_G[v1][v2]['weight'] += trafficE
    loading_G[v2][v1]['weight'] = loading_G[v1][v2]['weight']

    BW_usage_i[v1][v2] += trafficE
    BW_usage_i[v2][v1] = BW_usage_i[v1][v2]

    used_Edge_i[v1][v2] += 1
    used_Edge_i[v2][v1] = used_Edge_i[v1][v2]

    return topo_sliceG_i, loading_G, BW_usage_i, used_Edge_i, allo_G

def _updateC(C, L, estLoad, B):
    for v1, v2 in C.edges():
        tempC=(L[v1][v2]['weight']+estLoad-B[v1][v2]['weight'])
        if tempC < 0:
            tempC = 0
        C[v1][v2]['weight']=tempC / B[v1][v2]['weight']
        C[v2][v1]['weight']=C[v1][v2]['weight']
    return C

def _sumC(G, C):
    sum = 0
    for v1, v2 in G.edges():
        sum = sum+C[v1][v2]['weight']
    return sum


def _checkB(G, loading_G, EDGE_BANDWIDTH_G):
    for v1, v2 in G.edges():
        #some edge>0, not all edge<0
        if EDGE_BANDWIDTH_G[v1][v2]['weight']-loading_G[v1][v2]['weight']>0:
            return True
    #all edge<0
    return False


def set_remain_bandwidth_G(loading_G, EDGE_BANDWIDTH_G):
    remain_bandwidth_G = EDGE_BANDWIDTH_G.copy()
    for v1, v2 in remain_bandwidth_G.edges():
        remain_bandwidth_G[v1][v2]['weight']=EDGE_BANDWIDTH_G[v1][v2]['weight']-loading_G[v1][v2]['weight']
    return remain_bandwidth_G


def _getSpath(weight_G, tupS_v1, tupS_v2):
    try:
        spath_gen = nx.all_shortest_paths(weight_G, source = tupS_v1, target = tupS_v2, weight='weight')
        spath_gen = list(spath_gen)
        if spath_gen == None:
            print("no shortest path, may not connect")
        spath_gen = [p for p in sorted(spath_gen, key = lambda item:len(item), reverse = True)]
        return spath_gen
    except:
        return None

def _sortSpath(T, spath_gen, impact_G):
    sorted_spath_G_list=[]
    for spath in spath_gen:
        spath_G = _removeCycle(T, spath)
        sorted_spath_G_list.append(spath_G)
    sorted_spath_G_list = [p for p in sorted(sorted_spath_G_list, key = lambda item:_sumC(item, impact_G), reverse = False)]
    return sorted_spath_G_list

def _B_to_GB(input_B, num_float=1):
    input_B = str(input_B/1000000)
    if '.' in input_B:
        for x in range(len(input_B)):
            if input_B[x] == '.':
                try:
                    output_GB = str(input_B[:x+num_float+1])+"GB"
                except:
                    output_GB = str(input_B)+"GB"
    else:
        output_GB = str(input_B)                    
    return output_GB

def _draw_name_G(allo_G, loading_G, EDGE_BANDWIDTH_G, node_color, edge_color, font_color, topo_pos, showG, labels, dir_name, svg_name):
    nx.draw_networkx_edges(allo_G, topo_pos, edge_color="whitesmoke")

    node_labels={int(n):str(int(n)+1) for n in allo_G.nodes()}
    nx.draw_networkx(allo_G, topo_pos, labels=node_labels, node_color=node_color, font_color=font_color, edge_color = edge_color)

    if labels == True:
        remain_bandwidth_G = set_remain_bandwidth_G(loading_G, EDGE_BANDWIDTH_G)
        edge_labels = nx.get_edge_attributes(remain_bandwidth_G, 'weight')
        for v1, v2 in remain_bandwidth_G.edges():
            edge_labels[(v1,v2)]=_B_to_GB(edge_labels[(v1,v2)])
        nx.draw_networkx_edge_labels(showG, topo_pos, edge_labels = edge_labels)

    svg_path = os.path.join("./"+dir_name+"/"+svg_name)
    plt.savefig(svg_path, format="svg")
    plt.clf()


def _draw_subG(allo_G, loading_G, EDGE_BANDWIDTH_G, tupS, trafficE, node_dist_to_color, node_color, font_color, topo_pos, showG, i, icount, dir_name):
    nx.draw_networkx_edges(allo_G, topo_pos, edge_color="whitesmoke")

    node_labels={int(n):str(int(n)+1) for n in allo_G.nodes()}
    nx.draw_networkx(allo_G, topo_pos, labels=node_labels, nodelist = showG.nodes(), edgelist = showG.edges(), node_color=node_color, font_color=font_color, edge_color = node_dist_to_color[i+1], width = 4)

    remain_bandwidth_G = set_remain_bandwidth_G(loading_G, EDGE_BANDWIDTH_G)
    edge_labels = nx.get_edge_attributes(remain_bandwidth_G, 'weight')
    for v1, v2 in remain_bandwidth_G.edges():
        edge_labels[(v1,v2)]=_B_to_GB(edge_labels[(v1,v2)])
    nx.draw_networkx_edge_labels(allo_G, topo_pos, edge_labels = edge_labels)

    svg_name = "topo_sliceG["+str(i)+"]"+"_"+str(icount)+".svg"
    svg_path = os.path.join("./"+dir_name+"/"+svg_name)
    print(f"{i}-{icount}")
    plt.title("traffic type "+str(i+1)+" (switch "+r"$\bf{"+str(G_to_M(tupS[0]))+"}$"+" to switch "+r"$\bf{"+str(G_to_M(tupS[1]))+"}$"+"): "+r"$\bf{"+str(trafficE)+"}$"+" B")
    plt.savefig(svg_path, format="svg")
    plt.clf()
    return icount+1

def _draw_estcycle_G(allo_G, loading_G, EDGE_BANDWIDTH_G, tupS, trafficE, node_dist_to_color, node_color, font_color, topo_pos, showG, estG, i, icount, dir_name):
    nx.draw_networkx_edges(allo_G, topo_pos, edge_color="whitesmoke")

    node_labels={int(n):str(int(n)+1) for n in allo_G.nodes()}
    nx.draw_networkx(allo_G, topo_pos, labels=node_labels, nodelist = showG.nodes(), edgelist = showG.edges(), node_color=node_color, font_color=font_color, edge_color = node_dist_to_color[i+1], width = 4, style="solid")
    nx.draw_networkx(allo_G, topo_pos, labels=node_labels, nodelist = estG.nodes(), edgelist = estG.edges(), node_color=node_color, font_color=font_color, edge_color = "tab:gray", width = 4, style="dashed")

    remain_bandwidth_G = set_remain_bandwidth_G(loading_G, EDGE_BANDWIDTH_G)
    edge_labels = nx.get_edge_attributes(remain_bandwidth_G, 'weight')
    for v1, v2 in remain_bandwidth_G.edges():
        edge_labels[(v1,v2)]=_B_to_GB(edge_labels[(v1,v2)])
    for v1, v2 in estG.edges():
        edge_labels[(v1,v2)]=remain_bandwidth_G[v1][v2]['weight']
        edge_labels[(v1,v2)]=_B_to_GB(edge_labels[(v1,v2)])
    nx.draw_networkx_edge_labels(allo_G, topo_pos, edge_labels = edge_labels)

    svg_name = "topo_sliceG["+str(i)+"]"+str(icount)+".svg"
    svg_path = os.path.join("./"+dir_name+"/"+svg_name)
    print(f"{i}-{icount}")
    plt.title("traffic type "+str(i+1)+" (switch "+r"$\bf{"+str(G_to_M(tupS[0]))+"}$"+" to switch "+r"$\bf{"+str(G_to_M(tupS[1]))+"}$"+"): "+r"$\bf{"+str(trafficE)+"}$"+" B")
    plt.savefig(svg_path, format="svg")
    plt.clf()
    return icount+1




#algo start
def slice_algo(topo_G, SliceNum, EDGE_BANDWIDTH_G, HISTORYTRAFFIC, SliceDraw_ctrl, EstDraw_ctrl, ROUTING_TYPE, EXP_TYPE):
    #initialze
    allo_G = topo_G.copy()

    latency_G = allo_G.copy()
    for v1, v2 in latency_G.edges():
        latency_G[v1][v2]['weight']=1
        latency_G[v2][v1]['weight']=latency_G[v1][v2]['weight']
    loading_G =  allo_G.copy()
    for v1, v2 in loading_G.edges():
        loading_G[v1][v2]['weight']=0
        loading_G[v2][v1]['weight']=loading_G[v1][v2]['weight']

    remain_bandwidth_G = set_remain_bandwidth_G(loading_G, EDGE_BANDWIDTH_G)
    impact_G = allo_G.copy()
    impact_G = _updateC(impact_G, loading_G, 0, EDGE_BANDWIDTH_G)

    BW_usage =  {i:{u:{v:0 for v in allo_G.nodes()} for u in allo_G.nodes()}for i in range(SliceNum)}
    used_Edge = {i:{u:{v:0 for v in allo_G.nodes()} for u in allo_G.nodes()}for i in range(SliceNum)}

    topo_pos = nx.shell_layout(topo_G)

    #https://matplotlib.org/stable/gallery/color/named_colors.html
    node_color="tab:green"
    font_color="w"
    node_dist_to_color = {
        1: "tab:red",
        2: "tab:orange",
        3: "tab:olive",
        4: "tab:green",
        5: "tab:blue",
        6: "tab:purple",
        7: "tab:pink"
    }

    dir_name = "exp_toposvg"
    if not os.path.exists(dir_name):
        os.makedirs(dir_name)

    if SliceDraw_ctrl == True:
        #draw bandwidth
        svg_name = "topo_sliceG[7]"+"_G.svg"
        edge_color = "whitesmoke"
        labels = True
        _draw_name_G(allo_G, loading_G, EDGE_BANDWIDTH_G, node_color, edge_color, font_color, topo_pos, topo_G, labels, dir_name, svg_name)

    topo_sliceG = [ i for i in range(SliceNum) ]
    for i in range(SliceNum):
        #initialze
        topo_sliceG[i] = nx.Graph()
        topo_sliceG[i].add_nodes_from(allo_G.nodes())
        v_G = topo_sliceG[i].copy()

        #number +1 when call print svg
        icount = 0

        if SliceDraw_ctrl == True:
            #draw G.V
            svg_name = "topo_sliceG["+str(i)+"]"+"_V.svg"
            edge_color = "whitesmoke"
            labels = True
            _draw_name_G(allo_G, loading_G, EDGE_BANDWIDTH_G, node_color, edge_color, font_color, topo_pos, topo_G, labels, dir_name, svg_name)

        #sort
        sorted_HistoryTraffic = {k:v for k, v in sorted(HISTORYTRAFFIC[i].items(), key = lambda item:item[1], reverse = True)}


        #shortest path
        for tupS, trafficE in sorted_HistoryTraffic.items():
            if trafficE == 0:
                    break

            tupS_v1 = tupS[0]
            tupS_v2 = tupS[1]
            #print(f"({ tupS_v1}, { tupS_v2}):{trafficE}")

            """
            algo
            """

            if ROUTING_TYPE == "algo":
                impact_G = _updateC(impact_G, loading_G, trafficE, EDGE_BANDWIDTH_G)
                allo_G = _weightG(allo_G, latency_G)
                spath_gen = _getSpath(allo_G, tupS_v1, tupS_v2)
                if spath_gen == None:
                    print("no shortest path, may not connect")
                    continue
                else:
                    last_spath_gen = len(spath_gen)-1
                sorted_spath_G_list = _sortSpath(topo_sliceG[i], spath_gen, impact_G)

                for si, spath_G in enumerate(sorted_spath_G_list):
                    if _checkB(spath_G, loading_G, EDGE_BANDWIDTH_G) == True:
                        break
                    if si == last_spath_gen:
                        allo_G = _weightG(allo_G, impact_G)
                        spath_gen = _getSpath(allo_G, tupS_v1, tupS_v2)
                        sorted_spath_G_list = _sortSpath(topo_sliceG[i], spath_gen, impact_G)
            elif ROUTING_TYPE == "bellman-ford":
                allo_G = _weightG(allo_G, latency_G)
                spath_gen = _getSpath(allo_G, tupS_v1, tupS_v2)
                if spath_gen == None:
                    print("no shortest path, may not connect")
                    continue
                sorted_spath_G_list = _sortSpath(topo_sliceG[i], spath_gen, impact_G)

            """
            algo
            """

            #add path
            spath_G = sorted_spath_G_list[0]

            estcycle_G = topo_sliceG[i].copy()
            estcycle_G = _addPath(estcycle_G, spath_G)
            estB_G = v_G.copy()
            estB_G = _addPath(estB_G, spath_G)
            if EstDraw_ctrl == True:
                estadd_G = v_G.copy()
                estadd_G = _addPath(estadd_G, spath_G)
                icount=_draw_estcycle_G(allo_G, loading_G, EDGE_BANDWIDTH_G, tupS, trafficE, node_dist_to_color, node_color, font_color, topo_pos, topo_sliceG[i], estadd_G, i, icount, dir_name)

            for v1, v2 in spath_G.edges():
                topo_sliceG[i], loading_G, BW_usage[i], used_Edge[i], allo_G = _unionEdge(v1, v2, topo_sliceG[i], loading_G, EDGE_BANDWIDTH_G, BW_usage[i], used_Edge[i], trafficE, allo_G)
            if SliceDraw_ctrl == True:
                icount=_draw_subG(allo_G, loading_G, EDGE_BANDWIDTH_G, tupS, trafficE, node_dist_to_color, node_color, font_color, topo_pos, topo_sliceG[i], i, icount, dir_name)




        #spanning tree shortcut
        if _isConnected(topo_sliceG[i]) == True or EXP_TYPE == "scheduling":
            continue
        else:
            impact_G = _updateC(impact_G, loading_G, 0, EDGE_BANDWIDTH_G)
            shuffle_allo_edges = {}
            for v1, v2 in topo_G.edges():
                if v2 > v1:
                    w = impact_G[v1][v2]['weight']
                    e = (v1,v2)
                    if shuffle_allo_edges.get(w) == None:
                        shuffle_allo_edges[w] = []
                    shuffle_allo_edges[w].append(e)
            for k, v in shuffle_allo_edges.items():
                random.shuffle(v)
            sorted_allo_edges = {k:v for k, v in sorted(shuffle_allo_edges.items(), key = lambda item:item[0], reverse = False)}

            _isConnected_ctrl = 0
            for k, v in sorted_allo_edges.items():
                for tupS in v:
                    v1 = tupS[0]
                    v2 = tupS[1]
                    if used_Edge[i][v1][v2] == 0:
                        estcycle_G = topo_sliceG[i].copy()
                        estcycle_G.add_edge(v1,v2)
                        if EstDraw_ctrl == True:
                            estadd_G = v_G.copy()
                            estadd_G.add_edge(v1,v2)
                            icount=_draw_estcycle_G(topo_G, loading_G, EDGE_BANDWIDTH_G, tupS, trafficE, node_dist_to_color, node_color, font_color, topo_pos, topo_sliceG[i], estadd_G, i, icount, dir_name)
                        if _noCycle(estcycle_G):
                            topo_sliceG[i].add_edge(v1,v2)
                            used_Edge[i][v1][v2] += 1
                            used_Edge[i][v2][v1] += 1
                            if SliceDraw_ctrl == True:
                                icount=_draw_subG(topo_G, loading_G, EDGE_BANDWIDTH_G, tupS, trafficE, node_dist_to_color, node_color, font_color, topo_pos, topo_sliceG[i], i, icount, dir_name)
                    if _isConnected(topo_sliceG[i]) == True:
                        _isConnected_ctrl = 1
                        break
                if _isConnected_ctrl == 1:
                    break

    if SliceDraw_ctrl == True:
        #allcolor in one svg
        edge_labels = nx.get_edge_attributes(loading_G, 'weight')
        for v1, v2 in loading_G.edges():
            edge_labels[(v1,v2)]=_B_to_GB(edge_labels[(v1,v2)])
        nx.draw_networkx_edges(allo_G, topo_pos, edge_color="whitesmoke")

        for i in range(7):
            node_labels={int(n):str(int(n)+1) for n in allo_G.nodes()}
            nx.draw_networkx(allo_G, topo_pos, labels=node_labels, nodelist = topo_sliceG[i].nodes(), edgelist = topo_sliceG[i].edges(), node_color=node_color, font_color=font_color, edge_color = node_dist_to_color[i+1], width = 4)
        nx.draw_networkx_edge_labels(allo_G, topo_pos, edge_labels = edge_labels)

        svg_name = "topo_sliceG[7]_all.svg"
        svg_path = os.path.join("./"+dir_name+"/"+svg_name)
        plt.title("all tree loading")
        plt.savefig(svg_path, format="svg")
        plt.clf()

    return BW_usage, loading_G, topo_sliceG
import networkx as nx
import networkx.algorithms.tree.mst as mst
import networkx.algorithms.operators.binary as op
import matplotlib.pyplot as plt

import random
import os

def _removeCycle(T, spath):
    #checkCycle
    checkCycle = nx.utils.UnionFind(T.nodes())
    checkCycle.to_sets()
    for v1, v2 in T.edges():
        checkCycle.union(v1, v2) 

    #shortcut 
    if list(T.edges()) == []:
        #sp
        spath_graph = nx.Graph()
        for v1, v2 in zip(spath[0::1], spath[1::1]):
            spath_graph.add_edge(v1, v2)
        return spath_graph
    T_v1 = spath[0]
    T_v2 = spath[-1]    
    if checkCycle[T_v1] == checkCycle[T_v2]:
        Tpath_gen = nx.all_shortest_paths(T, source = T_v1 , target = T_v2)
        Tpath_gen = list(Tpath_gen)
        if  Tpath_gen == []:
            print("no simple path, may not connect")
        Tpath_gen = Tpath_gen[0]
        return_graph = nx.Graph()
        for v1, v2 in zip(Tpath_gen[0::1], Tpath_gen[1::1]):
            return_graph.add_edge(v1, v2)
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
                    checkCycle.union(v1, v2)
                    T.add_edge(v1, v2)
                    break
        vi = vi+1

    #check if new SP at T
    T_v1 = spath[0]
    T_v2 = spath[-1]
    
    #print(T.edges())
    Tpath_gen = nx.all_shortest_paths(T, source = T_v1 , target = T_v2)
    if  Tpath_gen == []:
        print("no simple path, may not connect")
    Tpath_gen = list(Tpath_gen)
    Tpath_gen = Tpath_gen[0]
    return_graph = nx.Graph()
    for v1, v2 in zip(Tpath_gen[0::1], Tpath_gen[1::1]):
        return_graph.add_edge(v1, v2)

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
            A.union(v1, v2)
        else:
            return False
    return True
    
    """
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
        G.add_edge(v1, v2)
    return G

def _unionEdge(v1, v2, topo_sliceG_i, loading_G, EDGE_BANDWIDTH_G, used_Edge_i, trafficE, allo_G):
    topo_sliceG_i.add_edge(v1, v2)
                            
    loading_G[v1][v2]['weight'] = loading_G[v1][v2]['weight'] + trafficE
    loading_G[v2][v1]['weight'] = loading_G[v1][v2]['weight']
 
    used_Edge_i[v1][v2] += 1
    used_Edge_i[v2][v1] += 1  

    return topo_sliceG_i, loading_G, used_Edge_i, allo_G

def _draw_subG(allo_G, loading_G, EDGE_BANDWIDTH_G, node_dist_to_color, topo_pos, showG, i, icount):
    remain_bandwidth_G = set_remain_bandwidth_G(loading_G, EDGE_BANDWIDTH_G)
    if i == 0 and icount == 0:
        labels = nx.get_edge_attributes(remain_bandwidth_G, 'weight')
        nx.draw_networkx_edges(allo_G, topo_pos)
        nx.draw_networkx(allo_G, topo_pos, edgelist = showG.edges(), edge_color = node_dist_to_color[i+1], width = 4)
        nx.draw_networkx_edge_labels(allo_G, topo_pos, edge_labels = labels)
        print(f"{i}-{icount}")
        #plt.show()
        plt.clf()
    labels = nx.get_edge_attributes(remain_bandwidth_G, 'weight')
    nx.draw_networkx_edges(allo_G, topo_pos)
    nx.draw_networkx(allo_G, topo_pos, edgelist = showG.edges(), edge_color = node_dist_to_color[i+1], width = 4)
    nx.draw_networkx_edge_labels(allo_G, topo_pos, edge_labels = labels)
    png_path= os.path.join("./exp_topopng/topo_sliceG["+str(i)+"]"+"_"+str(icount)+".png")
    print(f"{i}-{icount}")
    plt.savefig(png_path, dpi=300)  
    plt.clf()
    return icount+1

def _draw_estcycle_G(allo_G, loading_G, EDGE_BANDWIDTH_G, trafficE, node_dist_to_color, topo_pos, showG, estG, i, icount):
    remain_bandwidth_G = set_remain_bandwidth_G(loading_G, EDGE_BANDWIDTH_G)
    labels = nx.get_edge_attributes(remain_bandwidth_G, 'weight')
    for v1, v2 in estG.edges():
        labels[(v1, v2)]=str(labels[(v1, v2)])+"-"+str(trafficE)
    nx.draw_networkx_edges(allo_G, topo_pos)
    nx.draw_networkx(allo_G, topo_pos, edgelist = showG.edges(), edge_color = node_dist_to_color[i+1], width = 4, style="solid")
    nx.draw_networkx(allo_G, topo_pos, edgelist = estG.edges(), edge_color = node_dist_to_color[i+1], width = 4, style="dashed")
    nx.draw_networkx_edge_labels(allo_G, topo_pos, edge_labels = labels)
    png_path= os.path.join("./exp_topopng/topo_sliceG["+str(i)+"]"+"_"+str(icount)+".png")
    print(f"{i}-{icount}")
    plt.savefig(png_path, dpi=300)  
    plt.clf()
    return icount+1
        
def _updateC(C, L, estLoad, B):
    for v1, v2 in C.edges():
        tempC=(L[v1][v2]['weight']+estLoad-B[v1][v2]['weight'])
        if tempC<0:
            tempC=0
        C[v1][v2]['weight']=tempC/B[v1][v2]['weight']
        C[v2][v1]['weight']=C[v1][v2]['weight']
    return C

def _sumC(G, C):
    sum=0
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
    remain_bandwidth_G=EDGE_BANDWIDTH_G.copy()
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

#algo start
def slice_algo(topo_G, SliceNum, EDGE_BANDWIDTH_G, HISTORYTRAFFIC, SliceDraw_ctrl, EXP_TYPE): 
    SliceDraw_ctrl=0
    #initialze 
    allo_G = topo_G.copy()

    latency_G = allo_G.copy()
    for v1, v2 in latency_G.edges():
        latency_G[v1][v2]['weight']=1
        latency_G[v2][v1]['weight']=latency_G[v1][v2]['weight']
    loading_G=  allo_G.copy()
    for v1, v2 in loading_G.edges():
        loading_G[v1][v2]['weight']=0    
        loading_G[v2][v1]['weight']=loading_G[v1][v2]['weight'] 
    remain_bandwidth_G = set_remain_bandwidth_G(loading_G, EDGE_BANDWIDTH_G)
    impact_G = allo_G.copy()
    impact_G = _updateC(impact_G, loading_G, 0, EDGE_BANDWIDTH_G)

    used_Edge = {i:{u:{v:0 for v in allo_G.nodes()} for u in allo_G.nodes()}for i in range(SliceNum)}

    #https://matplotlib.org/stable/gallery/color/named_colors.html
    node_dist_to_color = {
        1: "tab:red", 
        2: "tab:orange", 
        3: "tab:olive", 
        4: "tab:green", 
        5: "tab:blue", 
        6: "tab:purple", 
        7: "tab:pink"
    }

    topo_pos = nx.spring_layout(topo_G, seed=2)
    #seed couuld be 2, 6, or more test to find
    topo_pos[0] = (1, 1)

    if SliceDraw_ctrl:
        remain_bandwidth_G = set_remain_bandwidth_G(loading_G, EDGE_BANDWIDTH_G)
        #draw G
        labels = nx.get_edge_attributes(remain_bandwidth_G, 'weight')
        nx.draw_networkx(topo_G, topo_pos)
        nx.draw_networkx_edge_labels(topo_G, topo_pos, edge_labels = labels)
        png_path= os.path.join("./exp_topopng/topo_sliceG[7]"+"_G.png")
        plt.savefig(png_path, dpi=300)
        plt.clf()

    topo_sliceG = [ i for i in range(SliceNum) ]
    for i in range(SliceNum):
        #initialze
        topo_sliceG[i] = nx.Graph()
        for v in allo_G.nodes():
            topo_sliceG[i].add_node(v)
        v_G = topo_sliceG[i].copy()

        #number +1 when call print png
        icount=0
        if SliceDraw_ctrl:
            #draw G.V
            nx.draw_networkx(topo_sliceG[i], topo_pos)
            png_path= os.path.join("./exp_topopng/topo_sliceG["+str(i)+"]"+"_V.png")
            plt.savefig(png_path, dpi=300)
            plt.clf()
            
        #sort
        sorted_HistoryTraffic = {k:v for k, v in sorted(HISTORYTRAFFIC[i].items(), key = lambda item:item[1], reverse = True)}
        
        #shortest path
        for tupS, trafficE in sorted_HistoryTraffic.items():
            if trafficE == 0:
                break    

            tupS_v1 = tupS[0]
            tupS_v2 = tupS[1]
            #print(f"({ tupS_v1}, { tupS_v2}):{trafficE}")

            impact_G = _updateC(impact_G, loading_G, trafficE, EDGE_BANDWIDTH_G)
            allo_G = _weightG(allo_G, latency_G)
            spath_gen = _getSpath(allo_G, tupS_v1, tupS_v2)
            if spath_gen == None:
                print("no shortest path, may not connect")
                continue
            else:
                last_spath_gen = len(spath_gen)-1
            sorted_spath_G_list = _sortSpath(topo_sliceG[i], spath_gen, impact_G)              

            for si,spath_G in enumerate(sorted_spath_G_list):
                if _checkB(spath_G, loading_G, EDGE_BANDWIDTH_G) == True:
                    break
                if si == last_spath_gen:
                    allo_G = _weightG(allo_G, impact_G)
                    spath_gen = _getSpath(allo_G, tupS_v1, tupS_v2)
                    sorted_spath_G_list = _sortSpath(topo_sliceG[i], spath_gen, impact_G)   

            #add path           
            spath_G = sorted_spath_G_list[0]
    
            estcycle_G = topo_sliceG[i].copy()
            estcycle_G = _addPath(estcycle_G, spath_G)
            estB_G = v_G.copy()
            estB_G = _addPath(estB_G, spath_G)
            if SliceDraw_ctrl:
                estadd_G = v_G.copy()
                estadd_G = _addPath(estadd_G, spath_G)                           
                icount=_draw_estcycle_G(allo_G, loading_G, EDGE_BANDWIDTH_G, trafficE, node_dist_to_color, topo_pos, topo_sliceG[i], estadd_G, i, icount)

            for v1,v2 in spath_G.edges():
                topo_sliceG[i], loading_G, used_Edge[i], allo_G = _unionEdge(v1, v2, topo_sliceG[i], loading_G, EDGE_BANDWIDTH_G, used_Edge[i], trafficE, allo_G)
            if SliceDraw_ctrl:                            
                icount=_draw_subG(allo_G, loading_G, EDGE_BANDWIDTH_G, node_dist_to_color, topo_pos, topo_sliceG[i], i, icount)            

        #spanning tree shortcut
        if _isConnected(topo_sliceG[i]) == True or EXP_TYPE == "scheduling":
            continue
        else:
            impact_G = _updateC(impact_G, loading_G, 0, EDGE_BANDWIDTH_G)
            shuffle_allo_edges = {}
            for v1, v2 in topo_G.edges():
                if v2 > v1:
                    w = impact_G[v1][v2]['weight']
                    e = (v1, v2)
                    if shuffle_allo_edges.get(w) == None:
                        shuffle_allo_edges[w] = []
                    shuffle_allo_edges[w].append(e)
            for k, v in shuffle_allo_edges.items():
                random.shuffle(v)
            sorted_allo_edges = {k:v for k, v in sorted(shuffle_allo_edges.items(), key = lambda item:item[0], reverse = False)}

            _isConnected_ctrl=0
            for k, v in sorted_allo_edges.items():
                for tupS in v:
                    v1 = tupS[0]
                    v2 = tupS[1]
                    if used_Edge[i][v1][v2] == 0:                        
                        estcycle_G = topo_sliceG[i].copy()                            
                        estcycle_G.add_edge(v1, v2)
                        if SliceDraw_ctrl: 
                            estadd_G = v_G.copy()
                            estadd_G.add_edge(v1, v2)
                            icount=_draw_estcycle_G(topo_G, loading_G, EDGE_BANDWIDTH_G, trafficE, node_dist_to_color, topo_pos, topo_sliceG[i], estadd_G, i, icount)
                        if _noCycle(estcycle_G):
                            topo_sliceG[i].add_edge(v1, v2)
                            used_Edge[i][v1][v2] += 1
                            used_Edge[i][v2][v1] += 1
                            if SliceDraw_ctrl:
                                icount=_draw_subG(topo_G, loading_G, EDGE_BANDWIDTH_G, node_dist_to_color, topo_pos, topo_sliceG[i], i, icount)           
                    if _isConnected(topo_sliceG[i]) == True:
                        _isConnected_ctrl=1
                        break
                if _isConnected_ctrl==1:
                    break
                    
    if SliceDraw_ctrl:
        labels = nx.get_edge_attributes(EDGE_BANDWIDTH_G, 'weight')
        nx.draw_networkx_edges(allo_G, topo_pos)
        for i in range(7):
            nx.draw_networkx(allo_G, topo_pos, edgelist = topo_sliceG[i].edges(), edge_color = node_dist_to_color[i+1], width = 4)
        nx.draw_networkx_edge_labels(allo_G, topo_pos, edge_labels = labels)
        png_path= os.path.join("./exp_topopng/topo_sliceG[7]"+"_all.png")
        plt.savefig(png_path, dpi=300)
        plt.clf()
    
    return topo_sliceG

#algo start
def bellman_ford(topo_G, SliceNum, EDGE_BANDWIDTH_G, HISTORYTRAFFIC, SliceDraw_ctrl): 
    SliceDraw_ctrl=0
    #initialze 
    allo_G = topo_G.copy()

    latency_G = allo_G.copy()
    for v1, v2 in latency_G.edges():
        latency_G[v1][v2]['weight']=1
        latency_G[v2][v1]['weight']=latency_G[v1][v2]['weight']
    loading_G=allo_G.copy()
    for v1, v2 in loading_G.edges():
        loading_G[v1][v2]['weight']=0    
        loading_G[v2][v1]['weight']=loading_G[v1][v2]['weight'] 
    remain_bandwidth_G = set_remain_bandwidth_G(loading_G, EDGE_BANDWIDTH_G)
    impact_G = allo_G.copy()
    impact_G = _updateC(impact_G, loading_G, 0, EDGE_BANDWIDTH_G)

    used_Edge = {i:{u:{v:0 for v in allo_G.nodes()} for u in allo_G.nodes()}for i in range(SliceNum)}

    #https://matplotlib.org/stable/gallery/color/named_colors.html
    node_dist_to_color = {
        1: "tab:red", 
        2: "tab:orange", 
        3: "tab:olive", 
        4: "tab:green", 
        5: "tab:blue", 
        6: "tab:purple", 
        7: "tab:pink"
    }

    topo_pos = nx.spring_layout(topo_G, seed=2)
    #seed couuld be 2, 6, or more test to find
    topo_pos[0] = (1, 1)

    if SliceDraw_ctrl:
        remain_bandwidth_G = set_remain_bandwidth_G(loading_G, EDGE_BANDWIDTH_G)
        #draw G
        labels = nx.get_edge_attributes(remain_bandwidth_G, 'weight')
        nx.draw_networkx(topo_G, topo_pos)
        nx.draw_networkx_edge_labels(topo_G, topo_pos, edge_labels = labels)
        png_path= os.path.join("./exp_topopng/topo_sliceG[7]"+"_G.png")
        plt.savefig(png_path, dpi=300)
        plt.clf()

    topo_sliceG = [ i for i in range(SliceNum) ]
    for i in range(SliceNum):
        #initialze
        topo_sliceG[i] = nx.Graph()
        for v in allo_G.nodes():
            topo_sliceG[i].add_node(v)
        v_G = topo_sliceG[i].copy()

        #number +1 when call print png
        icount=0
        if SliceDraw_ctrl:
            #draw G.V
            nx.draw_networkx(topo_sliceG[i], topo_pos)
            png_path= os.path.join("./exp_topopng/topo_sliceG["+str(i)+"]"+"_V.png")
            plt.savefig(png_path, dpi=300)
            plt.clf()
            
        #sort
        sorted_HistoryTraffic = {k:v for k, v in sorted(HISTORYTRAFFIC[i].items(), key = lambda item:item[1], reverse = True)}
        #shortest path
        for tupS, trafficE in sorted_HistoryTraffic.items():
            if trafficE == 0:
                break    

            tupS_v1 = tupS[0]
            tupS_v2 = tupS[1]
            
            
            allo_G = _weightG(allo_G, latency_G)
            spath_gen = _getSpath(allo_G, tupS_v1, tupS_v2)
            if spath_gen == None:
                print("no shortest path, may not connect")
                continue

            #add path           
            spath_G = _removeCycle(topo_sliceG[i], spath_gen[0])
    
            estcycle_G = topo_sliceG[i].copy()
            estcycle_G = _addPath(estcycle_G, spath_G)
            estB_G = v_G.copy()
            estB_G = _addPath(estB_G, spath_G)
            if SliceDraw_ctrl:
                estadd_G = v_G.copy()
                estadd_G = _addPath(estadd_G, spath_G)                           
                icount=_draw_estcycle_G(allo_G, loading_G, EDGE_BANDWIDTH_G, trafficE, node_dist_to_color, topo_pos, topo_sliceG[i], estadd_G, i, icount)

            for v1,v2 in spath_G.edges():
                topo_sliceG[i], loading_G, used_Edge[i], allo_G = _unionEdge(v1, v2, topo_sliceG[i], loading_G, EDGE_BANDWIDTH_G, used_Edge[i], trafficE, allo_G)
            if SliceDraw_ctrl:                            
                icount=_draw_subG(allo_G, loading_G, EDGE_BANDWIDTH_G, node_dist_to_color, topo_pos, topo_sliceG[i], i, icount)            

        #spanning tree 
        if _isConnected(topo_sliceG[i]) == True:
            continue
        else:
            impact_G = _updateC(impact_G, loading_G, 0, EDGE_BANDWIDTH_G)
            shuffle_allo_edges = {}
            for v1, v2 in topo_G.edges():
                if v2 > v1:
                    w = impact_G[v1][v2]['weight']
                    e = (v1, v2)
                    if shuffle_allo_edges.get(w) == None:
                        shuffle_allo_edges[w] = []
                    shuffle_allo_edges[w].append(e)
            for k, v in shuffle_allo_edges.items():
                random.shuffle(v)
            sorted_allo_edges = {k:v for k, v in sorted(shuffle_allo_edges.items(), key = lambda item:item[0], reverse = False)}

            _isConnected_ctrl=0
            for k, v in sorted_allo_edges.items():
                for tupS in v:
                    v1 = tupS[0]
                    v2 = tupS[1]
                    if used_Edge[i][v1][v2] == 0:                        
                        estcycle_G = topo_sliceG[i].copy()                            
                        estcycle_G.add_edge(v1, v2)
                        if SliceDraw_ctrl: 
                            estadd_G = v_G.copy()
                            estadd_G.add_edge(v1, v2)
                            icount=_draw_estcycle_G(topo_G, loading_G, EDGE_BANDWIDTH_G, trafficE, node_dist_to_color, topo_pos, topo_sliceG[i], estadd_G, i, icount)
                        if _noCycle(estcycle_G):
                            topo_sliceG[i].add_edge(v1, v2)
                            used_Edge[i][v1][v2] += 1
                            used_Edge[i][v2][v1] += 1
                            if SliceDraw_ctrl:
                                icount=_draw_subG(topo_G, loading_G, EDGE_BANDWIDTH_G, node_dist_to_color, topo_pos, topo_sliceG[i], i, icount)           
                    if _isConnected(topo_sliceG[i]) == True:
                        _isConnected_ctrl=1
                        break
                if _isConnected_ctrl==1:
                    break
                    
    if SliceDraw_ctrl:
        labels = nx.get_edge_attributes(EDGE_BANDWIDTH_G, 'weight')
        nx.draw_networkx_edges(allo_G, topo_pos)
        for i in range(7):
            nx.draw_networkx(allo_G, topo_pos, edgelist = topo_sliceG[i].edges(), edge_color = node_dist_to_color[i+1], width = 4)
        nx.draw_networkx_edge_labels(allo_G, topo_pos, edge_labels = labels)
        png_path= os.path.join("./exp_topopng/topo_sliceG[7]"+"_all.png")
        plt.savefig(png_path, dpi=300)
        plt.clf()
    
    return topo_sliceG
import networkx as nx
import networkx.algorithms.tree.mst as mst
import networkx.algorithms.operators.binary as op
import matplotlib.pyplot as plt


def _removeCycle(T, spath):
    #cycle by T, so find new SP at T
    findTreePath_graph=T.copy()

    #sp
    spath_graph=nx.Graph()
    for v1, v2 in zip(spath[0::1], spath[1::1]):
        spath_graph.add_edge(v1, v2)
    if list(T.edges()) == []:
        return spath_graph

    #2nd touch T
    checkCycle = nx.utils.UnionFind(T.nodes())
    checkCycle.to_sets()
    #edge on SP union T to new T
    removeCycle = nx.utils.UnionFind(T.nodes())
    removeCycle.to_sets()    

    #initial T
    T_root=[]
    for v1, v2 in T.edges():
        checkCycle.union(v1, v2)
        removeCycle.union(v1, v2)        
        if removeCycle[v1] not in T_root:
            T_root.append(removeCycle[v1])

    #if SP at T, return
    """T_v1_ctrl = False
    T_v2_ctrl = False
    T_v1=spath[0]
    T_v2=spath[-1]
    for v1,v2 in T.edges():
        if T_v1 == v1 or T_v1== v2:
            T_v1_ctrl = True
        if T_v2 == v1 or T_v2== v2:
            T_v2_ctrl = True
    if (T_v1_ctrl == True) and (T_v2_ctrl == True) and (removeCycle[T_v1] == removeCycle[T_v2]):
        Tpath_gen =nx.all_shortest_paths(findTreePath_graph, source = T_v1 , target = T_v2)
        Tpath_gen = list(Tpath_gen)
        Tpath_gen = Tpath_gen[0]
        spath_graph=nx.Graph()
        for v1, v2 in zip(Tpath_gen[0::1], Tpath_gen[1::1]):
            spath_graph.add_edge(v1, v2)
        print('====SP at T')
        return spath_graph"""
    
    prevroot=[]
    cyclepair=[]
    cyclepair.append([None, None])
    cyclepair_i=0

    #check edge in SP in which T
    for v1, v2 in zip(spath[0::1], spath[1::1]):
        #print(f'({v1}, {v2})')

        #SP cross tree
        if removeCycle[v1] in T_root and removeCycle[v2] in T_root:
            if removeCycle[v1] == removeCycle[v2]:
                #print('sameT')
                prevroot.append(removeCycle[v2])
                vt=v1
            elif removeCycle[v1] != removeCycle[v2]:
                #print('diffT')
                prevroot.append(removeCycle[v1])
                prevroot.append(removeCycle[v2])
                vt=v2
        elif removeCycle[v1] in T_root:
            #only v1 at T
            prevroot.append(removeCycle[v1])
            vt=v1
        elif removeCycle[v2] in T_root:
            #only v2 at T
            prevroot.append(removeCycle[v2])
            vt=v2

        #cycle pair first time in
        #cycle pair [0]=start,1st touch to [1]=end, 2nd touch
        if cyclepair[cyclepair_i][0] == None and cyclepair[cyclepair_i][1] == None:
            cyclepair[cyclepair_i][0]=vt 
            if vt == v1: 
                cyclepair[cyclepair_i][1]=v2
            else:
                cyclepair[cyclepair_i][1]=v1
        
        #cycle pair [0]=start,1st touch to [1]=end, 2nd touch
        if (v1, v2) in T.edges():
            cyclepair[cyclepair_i][0]=vt  
            continue
        elif removeCycle[vt] in prevroot and vt == cyclepair[cyclepair_i][0]:
            pass
        elif removeCycle[vt] not in prevroot:
            cyclepair[cyclepair_i][0]=vt  
            prevroot.append(removeCycle[vt])
        elif removeCycle[vt] in prevroot and vt != cyclepair[cyclepair_i][0]:
            cyclepair[cyclepair_i][1]=vt  



        #cycle happen, 2nd touch same T
        if checkCycle[v1] != checkCycle[v2]:
            checkCycle.union(v1, v2)
            findTreePath_graph.add_edge(v1, v2)
        else:
            print(cyclepair[cyclepair_i])
            #remove and insert path by tree
            try:
                insert_v0 = spath.index(cyclepair[cyclepair_i][0])
                insert_v1 = spath.index(cyclepair[cyclepair_i][1])
            except:
                print(f'T={T.edges()}')
                print(f'spath={spath}')

            removepath=spath[insert_v0:(insert_v1+1)]
            for v1, v2 in zip(removepath[0::1], removepath[1::1]):
                spath_graph.remove_edge(v1, v2)
            insertpath_gen =nx.all_shortest_paths(findTreePath_graph, source = cyclepair[cyclepair_i][0] , target = cyclepair[cyclepair_i][1])
            try:
                insertpath_gen = list(insertpath_gen)       
                insertpath = insertpath_gen[0]  
                for v1, v2 in zip(insertpath[0::1], insertpath[1::1]):
                    spath_graph.add_edge(v1, v2)
            except:
                pass
            
            #wair next pair
            cyclepair.append([None, None])
            cyclepair_i+=1
            cyclepair[cyclepair_i][0]=v2 
    
    
    #check if new SP at T
    T_v1_ctrl = False
    T_v2_ctrl = False
    T_v1=spath[0]
    T_v2=spath[-1]
    
    for v1,v2 in T.edges():
        if T_v1 == v1 or T_v1== v2:
            T_v1_ctrl = True
        if T_v2 == v1 or T_v2== v2:
            T_v2_ctrl = True
    if (T_v1_ctrl == True) and (T_v2_ctrl == True) and (checkCycle[T_v1] == checkCycle[T_v2]):
        Tpath_gen =nx.all_shortest_paths(findTreePath_graph, source = T_v1 , target = T_v2)
        Tpath_gen = list(Tpath_gen)
        Tpath_gen = Tpath_gen[0]
        spath_graph=nx.Graph()
        for v1, v2 in zip(Tpath_gen[0::1], Tpath_gen[1::1]):
            spath_graph.add_edge(v1, v2)

    return spath_graph

#gen graph
topo_G = nx.Graph()
nodelist=[i for i in range(100)]
edgelist= []
topo_G.add_nodes_from(nodelist)
topo_G.add_edges_from(edgelist)

for u,v in topo_G.edges():
    topo_G[u][v]['weight']=1

#T
tedgelist=[0]*100
tedgelist[0] = [(0,1),(1,2),]
tedgelist[1] = [(0,1),(1,2),]
tedgelist[2] = [(0,1),(1,2),(2,3),(3,4),]
tedgelist[3] = [(0,1),(1,2),(2,4),]
tedgelist[4] = [(0,1),(1,2),(2,3),(3,4),]
tedgelist[5] = [(0,1),(1,2),(3,4),(4,5),(6,7),(7,8),]


#SP
spathlist=[0]*100
spathlist[0] = [9,0,8]
spathlist[1] = [0,2]
spathlist[2] = [1,3]
spathlist[3] = [1,0,3,4,2]
spathlist[4] = [7,4,6,2,5,0]
spathlist[5] = [0,3,6,7,8,5]


#ans
returnlist=[0]*100
returnlist[0] = [(9, 0), (0, 8)]
returnlist[1] = [(0,1),(1,2),]
returnlist[2] = [(1,2),(2,3),]
returnlist[3] = [(1,2)]
returnlist[4] = [(7, 4), (4, 3), (2, 3), (2, 1), (0, 1)]
returnlist[5] = [(0, 3), (3,4),(4,5)]


if __name__ == "__main__":
    for i in range(6):
        select_list=i
        T=nx.Graph()
        for v in topo_G.nodes():
            T.add_node(v)
        T.add_edges_from(tedgelist[select_list])
        p=_removeCycle(T,spathlist[select_list]).edges()
        print(p)
        ans_G=nx.Graph()
        ans_G.add_edges_from(returnlist[select_list])
        print(ans_G.edges())
        if p == ans_G.edges():
            print(f'{select_list} got it')
        else:
            print(f'{select_list} GG')
import os
import shutil
import sys

sys.path.insert(1,'../')
from exp_config.exp_config import topo_G,topo_GNode0_alignto_mininetSwitchNum

from exp_utils.exp_utils import \
G_to_M


src_dir = "./"
if not os.path.exists(src_dir):
    os.makedirs(src_dir)
dst_dir = "./cs/"
if not os.path.exists(dst_dir):
    os.makedirs(dst_dir)
clinet_file = "client.py"
server_file = "server.py"

clinet_file=os.path.join(src_dir, clinet_file)
server_file=os.path.join(src_dir, server_file)

for s in topo_G.nodes():
    if len(topo_G.nodes[s]['host']) != 0:
        for h in topo_G.nodes[s]['host']:
            filename="client"+str(G_to_M(h))+".py"
            shutil.copy(clinet_file, os.path.join(dst_dir, filename))
for s in topo_G.nodes():
    if len(topo_G.nodes[s]['host']) != 0:
        for h in topo_G.nodes[s]['host']:
            filename="server"+str(G_to_M(h))+".py"
            shutil.copy(server_file , os.path.join(dst_dir, filename))
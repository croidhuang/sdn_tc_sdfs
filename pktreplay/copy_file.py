import os
import shutil

src_dir = "./"
dst_dir = "./cs/"
clinet_file = "client.py"
server_file = "server.py"

clinet_file=os.path.join(src_dir, clinet_file)    
server_file=os.path.join(src_dir, server_file)   

for i in range(1,7+1):
    filename="client"+str(i)+".py"
    shutil.copy(clinet_file, os.path.join(dst_dir, filename))    
for i in range(8,14+1):
    filename="server"+str(i)+".py"
    shutil.copy(server_file , os.path.join(dst_dir, filename))    
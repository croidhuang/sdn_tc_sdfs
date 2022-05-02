import os
from pathlib import Path
import numpy as np
import pandas as pd

filepath='./timerecord'
outputpath='./timerecord'

client_timerecord=[0]*7
server_timerecord=[0]*7
timerecord=[0]*7
for i in range(7):
    client_timerecord[i] = []
    server_timerecord[i] = []
    timerecord[i] = []

file_list=[1]*7

for csv_name in os.listdir(filepath):
    if csv_name.endswith('_client.csv') or csv_name.endswith('_server.csv'):
        i=-1
        if csv_name.endswith('_client.csv'):
            typelen=len('_client.csv')
            i=csv_name[:(typelen*-1)]
        elif csv_name.endswith('_server.csv'):
            typelen=len('_server.csv')
            i=csv_name[:(typelen*-1)]
        else:
            print(f'{csv_name} gg')
        i=int(i)

        if file_list[i]==1:      
            try:
                loadfile=filepath+'/'+str(i)+'_client.csv'
                print(f'{i}...')
                client_timerecord[i]=np.loadtxt(loadfile,dtype="float",delimiter=",")
            except:
                print(f'{i} no client')
                file_list[i]=0
                continue
            try:
                loadfile=filepath+'/'+str(i)+'_server.csv'
                server_timerecord[i]=np.loadtxt(loadfile,dtype="float",delimiter=",")
            except:
                print(f'{i} no server')
                file_list[i]=0
                continue
            
            timerecord[i]=[0]*len(client_timerecord[i])
            for r in range(len(client_timerecord[i])):
                timerecord[i][r] = abs(server_timerecord[i][r]-client_timerecord[i][r])

            output_name=outputpath+'/'+str(i)+'_latency'+'.csv'
            np.savetxt(output_name,timerecord[i],fmt="%lf",delimiter=",")

            print(f'{i} Done')

d={}
for i in range(7):
    d[i]=timerecord[i]

output_name=outputpath+'/'+'_latency'+'.csv'
df = pd.DataFrame(dict([(k,pd.Series(v)) for k,v in d.items()]))
df.to_csv(output_name)
                                                              

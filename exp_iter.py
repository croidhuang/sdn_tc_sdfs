import time
from subprocess import Popen
import json
import os

a=["algo",       "sp_sortC"]
b=[False,        "MAX"]
c=["routing",    "fake", ]
d=["est_avg",    "port"]


for aa in a:
    for bb in b:
        for cc in c:
            for dd in d:
                exp_iter={}
                exp_iter['ROUTING_TYPE'] = aa
                exp_iter['SCHEDULER_TYPE'] = bb
                exp_iter['EXP_TYPE'] =  cc
                exp_iter['DYNBW_TYPE'] = dd
                timestamp = time.time()+(3*60)
                struct_time = time.localtime(timestamp)
                exp_iter['timestring'] = time.strftime("%Y-%m-%d %H:%M:%S", struct_time)        
                json.dump(exp_iter, open("exp_iter.txt","w"))

                username='croid'
                homedir = os.path.expanduser('~'+username)
                try:
                    Popen(["python3","-u",'mininet/custom/custom_example_nxtomini.py'],cwd=homedir)
                except:
                    print('change exp_iter.py username')
                
                time.sleep(4*60+240)  
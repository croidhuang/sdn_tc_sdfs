import time
from subprocess import Popen
import json
import os

username='croid'
a=["sp_sortC","bellman-ford"]
#"algo",       "sp_sortC",                 "bellman-ford"
b=[False,]
#False,        "MAX",                      "min",          "random",   "algo"
c=["square_routing",]
 #"routing",    "scheduling_routing",      "square_routing", "two_routing",     "scheduling"
d=["est_avg",   ]
#"est_avg",    "port"

for aa in a:
    for bb in b:
        for cc in c:
            for dd in d:
                for i in range(1):
                    exp_iter={}
                    exp_iter['ROUTING_TYPE'] = aa
                    exp_iter['SCHEDULER_TYPE'] = bb
                    exp_iter['EXP_TYPE'] =  cc
                    exp_iter['DYNBW_TYPE'] = dd
                    timestamp = time.time()+(3*60)
                    struct_time = time.localtime(timestamp)
                    exp_iter['timestring'] = time.strftime("%Y-%m-%d %H:%M:%S", struct_time)
                    json.dump(exp_iter, open("exp_iter.txt","w"))

                    homedir = os.path.expanduser('~'+username)
                    try:
                        Popen(["mn","-c"],cwd=homedir)
                        time.sleep(5)
                        Popen(["python3","-u",'mininet/custom/custom_example_nxtomini.py'],cwd=homedir)
                    except:
                        print('change exp_iter.py username')

                    time.sleep(4*60+240)
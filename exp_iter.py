import time
from subprocess import Popen
import json
import os

username = 'croid'
ROUTING_TYPE_list = ["sp_sortC"]
#"algo",       "sp_sortC",                 "bellman-ford"
SCHEDULER_TYPE_list = ["MAX"]
#False,        "MAX",                      "min",          "random",   "algo"
EXP_TYPE_list = ["dymsquare_routing",]
 #"routing",    "scheduling_routing",      "square_routing", "two_routing",     "scheduling"
DYNBW_TYPE_list = ["est_avg",   ]
#"est_avg",    "rt_port"

for ROUTING_TYPE in ROUTING_TYPE_list:
    for SCHEDULER_TYPE in SCHEDULER_TYPE_list:
        for EXP_TYPE in EXP_TYPE_list:
            for DYNBW_TYPE in DYNBW_TYPE_list:
                for i in range(3):
                    #var
                    exp_iter = {}
                    exp_iter['ROUTING_TYPE'] = ROUTING_TYPE
                    exp_iter['SCHEDULER_TYPE'] = SCHEDULER_TYPE
                    exp_iter['EXP_TYPE'] =  EXP_TYPE
                    exp_iter['DYNBW_TYPE'] = DYNBW_TYPE

                    #file sned var to config
                    prepare_time = 1*60
                    timestamp = time.time() + prepare_time
                    struct_time = time.localtime(timestamp)
                    exp_iter['timestring'] = time.strftime("%Y-%m-%d %H:%M:%S", struct_time)
                    json.dump(exp_iter, open("exp_iter.txt","w"))

                    #username popen mininet
                    homedir = os.path.expanduser('~'+username)
                    try:
                        Popen(["mn","-c"],cwd = homedir)
                        time.sleep(5)
                        Popen(["python3","-u",'mininet/custom/custom_example_nxtomini.py'],cwd = homedir)
                    except:
                        print('change exp_iter.py username')

                    exp_time = 4*60
                    cooldown_time = 2*60
                    time.sleep(exp_time + cooldown_time)
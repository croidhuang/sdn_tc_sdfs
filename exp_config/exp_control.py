ctrl_ROUTING_TYPE = "algo" #bellman-ford, algo
ctrl_SCHEDULER_TYPE = 0  #0,1,"random","MAX","min","algo",
ctrl_EXP_TYPE = "routing" #"scheduling","routing"

ctrl_RANDOM_SEED_NUM = 3 #manual

ctrl_timestring = "2022-04-09 19:10:00" #manual


"""
#not work, will crash
import subprocess

proc = subprocess.Popen(["cd $home","sudo python3 mininet/custom/custom_example_nxtomini.py"], shell=True, stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
while True:
    line = proc.stdout.readline()
    if not line:
        break
    print(line)
"""
from matplotlib import pyplot as plt
import seaborn as sns

import numpy as np
import pandas as pd

import pprint
import os
import csv


xlabel=["C0\nChat",
"C1\nEmail",
"C2\nFile Transfer",
"C3\nStreaming",
"C4\nP2P",
"C5\nVoIP",
"C6\nBrowser",]

ylabel=["C0\nChat",
"C1\nEmail",
"C2\nFile Transfer",
"C3\nStreaming",
"C4\nP2P",
"C5\nVoIP",
"C6\nBrowser",]

human_dict={ 0:[0,6],
            1:[1,4],
            2:[3,8,9],
            3:[7,12,14],
            4:[15],
            5:[5,10,11,13],
            6:[2,16],   
        }

with open('cmreport.csv', newline='', encoding='utf-8-sig') as csvfile:
    rows = csv.reader(csvfile)
    rows = list(rows)

    app_to_class_dict= {}
    for classi,v in human_dict.items() :
        for appi in v :
            app_to_class_dict[appi]=classi

    cm_report=[ [0 for i in range(len(human_dict))] for j in range(len(human_dict))]

    for i,row in enumerate(rows):
        for j,col in enumerate(row):
            cm_report[app_to_class_dict[i]][app_to_class_dict[j]] += int(col)


    sum_col  =[0 for i in range(len(human_dict))]
    for i,row in enumerate(cm_report):
        for j,col in enumerate(row):
            sum_col[i] += int(col)

    for i,row in enumerate(cm_report):
        for j,col in enumerate(row):
            cm_report[i][j] = cm_report[i][j]/sum_col[i]
            cm_report[i][j] = round(cm_report[i][j], 4)

sns.set(font_scale=0.7)
ax = sns.heatmap(pd.DataFrame(cm_report).iloc[:,:], annot = True, fmt=".4g", cmap = "Blues", xticklabels=xlabel, yticklabels=ylabel)
plt.ylabel("True label")
plt.xlabel("Predicted label")
plt.subplots_adjust(left=0.15)
pngoutput_path = os.path.join('./'+ 'color'+'.'+'confusion_matrix'+'.'+'randomfroest' +'.svg')
plt.savefig(pngoutput_path, format='svg')
plt.clf()
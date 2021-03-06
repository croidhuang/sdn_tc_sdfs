import os

b255dict={
    0:'IPv4_Version_IHL___IPv6_Version_Traffic_class1', 
    1:'IPv4_DSCP_ECN___IPv6_Traffic_class2_Flow_label1', 
    2:'IPv4_Total_Length1___IPv6_Flow_label2', 
    3:'IPv4_Total_Length2___IPv6_Flow_label3', 
    4:'IPv4_Id1___IPv6_Payload_length1', 
    5:'IPv4_Id2___IPv6_Payload_length2', 
    6:'IPv4_Flags_Fragment_Offset1___IPv6_Next_header', 
    7:'IPv4_Fragment_Offset2___IPv6_Hop_limit', 
    8:'IPv4_Time_To_Live___IPv6_src_IP_Addr1', 
    9:'IPv4_Protocol___IPv6_src_IP_Addr2', 
    10:'IPv4_Header_Checksum1___IPv6_src_IP_Addr3', 
    11:'IPv4_Header_Checksum2___IPv6_src_IP_Addr4', 
    12:'IPv4_src_IP_Addr1___IPv6_src_IP_Addr5', 
    13:'IPv4_src_IP_Addr2___IPv6_src_IP_Addr6', 
    14:'IPv4_src_IP_Addr3___IPv6_src_IP_Addr7', 
    15:'IPv4_src_IP_Addr4___IPv6_src_IP_Addr8', 
    16:'IPv4_dst_IP_Addr1___IPv6_src_IP_Addr9', 
    17:'IPv4_dst_IP_Addr2___IPv6_src_IP_Addr10', 
    18:'IPv4_dst_IP_Addr3___IPv6_src_IP_Addr11', 
    19:'IPv4_dst_IP_Addr4___IPv6_src_IP_Addr12', 
    20:'TCP_UDP_src_port1___IPv6_src_IP_Addr13', 
    21:'TCP_UDP_src_port2___IPv6_src_IP_Addr14', 
    22:'TCP_UDP_dst_port1___IPv6_src_IP_Addr15', 
    23:'TCP_UDP_dst_port2___IPv6_src_IP_Addr16', 
    24:'TCP_seqnum1_UDP_length1___IPv6_dst_IP_Addr1', 
    25:'TCP_seqnum2_UDP_length2___IPv6_dst_IP_Addr2', 
    26:'TCP_seqnum3_UDP_checksum1___IPv6_dst_IP_Addr3', 
    27:'TCP_seqnum4_UDP_checksum2___IPv6_dst_IP_Addr4', 
    28:'TCP_acknum1___IPv6_dst_IP_Addr5', 
    29:'TCP_acknum2___IPv6_dst_IP_Addr6', 
    30:'TCP_acknum3___IPv6_dst_IP_Addr7', 
    31:'TCP_acknum4___IPv6_dst_IP_Addr8', 
    32:'TCP_Data_offset_Reserved_NS___IPv6_dst_IP_Addr9', 
    33:'TCP_flagbit___IPv6_dst_IP_Addr10', 
    34:'TCP_Window_Size1___IPv6_dst_IP_Addr11', 
    35:'TCP_Window_Size2___IPv6_dst_IP_Addr12', 
    36:'TCP_Checksum1___IPv6_dst_IP_Addr13', 
    37:'TCP_Checksum2___IPv6_dst_IP_Addr14', 
    38:'TCP_Urgent_pointer1___IPv6_dst_IP_Addr15', 
    39:'TCP_Urgent_pointer2___IPv6_dst_IP_Addr16', 
}

ipandport_dict={
    0: 'src_ip_1', 
    1: 'src_ip_2', 
    2: 'src_ip_3', 
    3: 'src_ip_4', 
    4: 'src_ip_5', 
    5: 'src_ip_6', 
    6: 'src_ip_7', 
    7: 'src_ip_8', 
    8: 'src_ip_9', 
    9: 'src_ip_10', 
    10: 'src_ip_11', 
    11: 'src_ip_12', 
    12: 'src_ip_13', 
    13: 'src_ip_14', 
    14: 'src_ip_15', 
    15: 'src_ip_16', 
    16: 'dst_ip_1', 
    17: 'dst_ip_2', 
    18: 'dst_ip_3', 
    19: 'dst_ip_4', 
    20: 'dst_ip_5', 
    21: 'dst_ip_6', 
    22: 'dst_ip_7', 
    23: 'dst_ip_8', 
    24: 'dst_ip_9', 
    25: 'dst_ip_10', 
    26: 'dst_ip_11', 
    27: 'dst_ip_12', 
    28: 'dst_ip_13', 
    29: 'dst_ip_14', 
    30: 'dst_ip_15', 
    31: 'dst_ip_16', 
    32: 'src_port_1', 
    33: 'src_port_2', 
    34: 'dst_port_1', 
    35: 'dst_port_2', 
 }

headerfield_dict={
    0: 'ipv4_version', 
    1: 'ipv4_ihl', 
    2: 'ipv4_tos', 
    3: 'ipv4_len', 
    4: 'ipv4_id', 
    5: 'ipv4_flags', 
    6: 'ipv4_frag', 
    7: 'ipv4_ttl', 
    8: 'ipv4_proto', 
    9: 'ipv4_chksum', 
    10: 'ipv4_src', 
    11: 'ipv4_dst', 
    12: 'ipv4_options', 
    13: 'ipv6_version', 
    14: 'ipv6_tc', 
    15: 'ipv6_fl', 
    16: 'ipv6_plen', 
    17: 'ipv6_nh', 
    18: 'ipv6_hlim', 
    19: 'ipv6_src', 
    20: 'ipv6_dst', 
    21: 'tcp_sport', 
    22: 'tcp_dport', 
    23: 'tcp_seq', 
    24: 'tcp_ack', 
    25: 'tcp_dataofs', 
    26: 'tcp_reserved', 
    27: 'tcp_flags', 
    28: 'tcp_window', 
    29: 'tcp_chksum', 
    30: 'tcp_urgptr', 
    31: 'tcp_options', 
    32: 'udp_sport', 
    33: 'udp_dport', 
    34: 'udp_len', 
    35: 'udp_chksum'
}



#??????????????????
try:
    valid_modelpath = './models/b255v6 RandomForest choice_random=0.004 train_size=0.8 test_size=0.2 choice_split=3 choice_train=2 1630563027.216647.pkl'
except:
    print("no model file, please check")

#??????????????????
choice_dataset = 'b255v6'   
outputpath = './'

"""
#?????????????????????????????????????????????*.parquet???*.csv
"""
def dataset_path(choice_dataset):
    if choice_dataset == 'b255v6':
        trainpath = './pcap/b255v6/*.parquet'
        testpath = './pcap/b255v6/*.parquet'
        headerdict = b255dict
    elif choice_dataset == 'ipandport':
        trainpath = './pcap/ipandport/*.parquet'
        testpath = './pcap/ipandport/*.parquet'
        headerdict = ipandport_dict
    elif choice_dataset == 'headerfield':
        trainpath = './pcap/headerfield/*.parquet'
        testpath = './pcap/headerfield/*.parquet' 
        headerdict = headerfield_dict   
    else:
        print("choice_dataset gg")

    return trainpath, testpath, headerdict

trainpath, testpath, headerdict = dataset_path(choice_dataset)

#choice_random??????pcap?????????????????????, ??????0???????????????(1???1????????????1), b255????????????10, 000, ??????11, 000, 000???????????????GG
#minqty?????????????????????, replace?????????????????????????????????
choice_random = 0.004
minqty_threshold = 100
randomreplace = 'False'
#size?????????????????????, 1???0???????????????
train_size = 0.8
test_size = 0.2

#1????????????
#2train_test_split same rate "all class"
#3RandomUnderSampler resample to "min(all class)"
#4StratifiedShuffleSplit same rate "each class"
choice_split = 3

#1????????????
#2???train, test
#3??????train, test
choice_train = 2

#??????????????????????????????
show_ctrl = False
#??????????????????????????????????????????????????????
title_ctrl = True
#?????????????????????????????????
cal_confusion_matrix = True
#??????????????????????????????(????????????????????????)
cal_tree_structure = False

#??????????????????
# 1clf
# 2forest
# 3svc
# 4c45clf
# 5clfe
# 6lightgbm
# 9valid
choice_classfier = 2



"""
##################################################################################
"""

#sklearn??????set?????????numpy
import numpy as np
#??????parquet?????????column
import pandas as pd
#???datatype csv???list?????????float
from ast import literal_eval
import ast
#??????mergeparquet
import glob as glob

#??????
from matplotlib import pyplot as plt
#?????????heatmap??????
import seaborn as sns
import itertools
#????????????
from datetime import datetime, timezone, timedelta

#???decision tree
import pydotplus
from sklearn.tree import export_graphviz
#???model
import joblib

from sklearn.model_selection import train_test_split, StratifiedShuffleSplit
from sklearn.tree import DecisionTreeClassifier
from sklearn.svm import SVC
from sklearn import tree, ensemble
from sklearn.metrics import classification_report, confusion_matrix

#?????????data
#https://imbalanced-learn.org/stable/
from imblearn.under_sampling import RandomUnderSampler

#RaczeQ???decision tree c4.5
#https://github.com/RaczeQ/scikit-learn-C4.5-tree-classifier
from c45RaczeQ.c45 import C45

#LightGBM???sklearn??????
#https://lightgbm.readthedocs.io/en/latest/
import lightgbm

#weka
import os
import traceback


"""
#??????????????????????????????
#RandomUnderSampler resample to "min(all class)"
"""

def stratified_split(y, train_size):
    def split_class(y, label, train_size):
        indices = np.flatnonzero(y == label)
        n_train = int(indices.size*train_size)
        train_index = indices[:n_train]
        test_index = indices[n_train:]
        return (train_index, test_index)
    idx = [split_class(y, label, train_size) for label in np.unique(y)]
    train_index = np.concatenate([train for train, _ in idx])
    test_index = np.concatenate([test for _, test in idx])
    return train_index, test_index

"""
dataset????????????class
"""
class sklearn_class:
    def __init__(self, trainpath, testpath):
        self.trainpath = trainpath
        self.testpath = testpath
        self.train_glob_merged_data = []
        self.test_glob_merged_data = []

    def input_func(self, dataset_id, file_id):
        #merge??????
        if dataset_id == 'train':
            glob_files = glob.glob(self.trainpath)
        elif dataset_id == 'test':
            glob_files = glob.glob(self.testpath)
        else:
            print('dataset_id gg')

        glob_merged_data = []
        glob_data = []
        for f in glob_files:
            reader = []
            if file_id == 'csv':
                reader = pd.read_csv(f, engine='c')
            elif file_id == 'parquet':
                reader = pd.read_parquet(f, engine='fastparquet')
            else:
                print('file_id gg')

            if not choice_random == 0:
                len_index = len(reader.index)
                if isinstance(choice_random, int):
                    minqty = int(choice_random)
                    if minqty > len_index:
                        minqty = len_index
                else:
                    minqty = int(len_index*choice_random)
                if minqty-minqty_threshold <= 0:
                    minqty = minqty_threshold
                reader = reader.sample(n=minqty, replace=randomreplace)
            glob_data.append(reader)
            glob_merged_data = pd.concat(glob_data, ignore_index=True)

        if dataset_id == 'train':
            self.train_glob_merged_data = glob_merged_data
        elif dataset_id == 'test':
            self.test_glob_merged_data = glob_merged_data
        else:
            print('dataset_id gg')
        #?????????????????????????????????
        #print(glob_merged_data)

    def input_train_csv(self):
        #merge??????csv
        self.input_func(dataset_id='train', file_id='csv')

    def input_train_parquet(self):
        #merge??????parquet
        self.input_func(dataset_id='train', file_id='parquet')

    def input_test_csv(self):
        self.input_func(dataset_id='test', file_id='csv')

    def input_test_parquet(self):
        self.input_func(dataset_id='test', file_id='parquet')

    def split_numpy_func(self, dataset_id, file_id):
        #??????numpy??????sklearn??????
        if dataset_id == 'train':
            glob_merged_data = self.train_glob_merged_data            
        elif dataset_id == 'test':
            glob_merged_data = self.test_glob_merged_data
        else:
            print('dataset_id gg')

        #for weka
        """
        from arff import arff #pandas2arff
        self.weka_output_name=outputpath+'\\'+'train.arff'
        arff.toARFF(glob_merged_data, self.weka_output_name)
        """

        if file_id == 'csv':
            df = glob_merged_data['feature'].values
            X = [ast.literal_eval(j) for j in df]
        elif file_id == 'parquet':
            X = glob_merged_data['feature'].values.reshape(-1,).tolist()
        else:
            print('file_id gg')
        X = np.array(X)
        y = glob_merged_data['app_label'].values.reshape(-1,).tolist()
        y = np.array(y)
        #???????????????????????????GG
        #print(X, y)

        if choice_split == 1:
            #all
            X_train = X
            y_train = y
            X_test = X
            y_test = y
        elif choice_split == 2:
            #train_test_split same rate "all class"
            X_train, X_test, y_train, y_test = train_test_split(X, y, train_size = train_size, test_size = test_size)
        elif choice_split == 3:
            #RandomUnderSampler resample to "min(all class)"
            under_X_train, under_X_test, under_y_train, under_y_test = train_test_split(X, y, train_size = train_size, test_size = test_size)
            rus = RandomUnderSampler(random_state=0)
            X_train, y_train = rus.fit_resample(under_X_train, under_y_train)
            X_test, y_test = rus.fit_resample(under_X_test, under_y_test)
        elif choice_split == 4:
            #StratifiedShuffleSplit same rate "each class"
            train_index, test_index = stratified_split(y, train_size)
            X_train = X[train_index]
            y_train = y[train_index]
            X_test = X[test_index]
            y_test = y[test_index]
        else:
            print('choice_split gg')

        if dataset_id == 'train':
            self.train_X_train = X_train
            self.train_y_train = y_train
            self.train_X_test = X_test
            self.train_y_test = y_test
        elif dataset_id == 'test':
            self.test_X_train = X_train
            self.test_y_train = y_train
            self.test_X_test = X_test
            self.test_y_test = y_test
        else:
            print('dataset_id gg')

    def train_numpy_csv(self):
        #trainset??????csv
        self.split_numpy_func(dataset_id='train', file_id='csv')

    def train_numpy_parquet(self):
        #trainset??????parquet
        self.split_numpy_func(dataset_id='train', file_id='parquet')

    def test_numpy_csv(self):
        self.split_numpy_func(dataset_id='test', file_id='csv')

    def test_numpy_parquet(self):
        self.split_numpy_func(dataset_id='test', file_id='parquet')
        

"""
#classifier
"""


def classifier_clf(X_train, y_train, X_test):
    #Decision Tree
    classifier = 'DecisionTree'
    clf = DecisionTreeClassifier(max_leaf_nodes=128, random_state=0)
    clf.fit(X_train, y_train)
    print_tree(clf, classifier)
    y_test_predicted = clf.predict(X_test)
    save_models(clf, classifier)
    return y_test_predicted, classifier


def classifier_forest(X_train, y_train, X_test):
    #random forest
    classifier = 'RandomForest'
    forest = ensemble.RandomForestClassifier(n_estimators=500, criterion="entropy", class_weight="balanced")
    forest.fit(X_train, y_train)
    y_test_predicted = forest.predict(X_test)
    save_models(forest, classifier)
    return y_test_predicted, classifier


def classifier_svc(X_train, y_train, X_test):
    #svm
    classifier = 'SupportVectorMachine'
    svc = SVC(random_state=0)
    svc.fit(X_train, y_train)
    y_test_predicted = svc.predict(X_test)
    save_models(svc, classifier)
    return y_test_predicted, classifier


def classifier_c45clf(X_train, y_train, X_test):
    #c4.5
    classifier = 'C4.5'
    c45clf = C45()
    c45clf.fit(X_train, y_train)
    #print_tree(c45clf, classifier)
    y_test_predicted = c45clf.predict(X_test)
    save_models(c45clf, classifier)
    return y_test_predicted, classifier


def classifier_clfe(X_train, y_train, X_test):
    #Decision Tree entropy
    classifier = 'DecisionTreeEntropy'
    clfe = DecisionTreeClassifier(criterion='entropy', max_leaf_nodes=64, random_state=0)
    clfe.fit(X_train, y_train)
    #print_tree(clfe)
    y_test_predicted = clfe.predict(X_test)
    save_models(clfe, classifier)
    return y_test_predicted, classifier

def classifier_lightgbm(X_train, y_train, X_test):
    #Decision Tree
    classifier = 'LightGBM'
    params_sklearn = {
        'learning_rate': 0.1, 
        'max_bin': 64, 
        'num_leaves': 128, 
        'max_depth': 16, 

        'reg_alpha': 0.1, 
        'reg_lambda': 0.2, 

        'objective': 'multiclass', 
        'n_estimators': 512, 
    }

    gbm = lightgbm.LGBMClassifier(**params_sklearn)
    gbm.fit(X_train, y_train)
    y_test_predicted = gbm.predict(X_test)
    save_models(gbm, classifier)
    return y_test_predicted, classifier

def classifier_valid(readclf, X_test):
    #validation
    classifier = 'validation'
    clf = readclf
    y_test_predicted = clf.predict(X_test)
    return y_test_predicted, classifier





"""
result
"""


def file_timestamp():
    rt = timezone(timedelta(hours=+8))
    titlet = str(datetime.now().timestamp())
    patht = datetime.now(rt).isoformat(timespec="seconds")
    return titlet, patht


def print_result(test_y_test, y_test_predicted, classifier):
    #print(test_y_test, y_test_predicted)
    ID_TO_APP = {
    0: 'AIM Chat', 
    1: 'Email', 
    2: 'Facebook', 
    3: 'FTPS', 
    4: 'Gmail', 
    5: 'Hangouts', 
    6: 'ICQ', 
    7: 'Netflix', 
    8: 'SCP', 
    9: 'SFTP', 
    10: 'Skype', 
    11: 'Spotify', 
    12: 'Torrent', 
    13: 'Tor', 
    14: 'Vimeo', 
    15: 'Voipbuster', 
    16: 'Youtube', 
    }
    labelslist = []
    targetnameslist = []
    for k, v in ID_TO_APP.items():
        labelslist.append(k)
        targetnameslist.append(v)

    #result
    #print(test_y_test)
    patht, titlet = file_timestamp()
    result_title = classifier+'\n'+trainpath+'\n'+titlet
    dir_name = "results"
    if not os.path.exists(dir_name):
        os.makedirs(dir_name)
    svg_title = patht

    #colormaps cmap=
    #https://matplotlib.org/stable/tutorials/colors/colormaps.html
    #confusion_matrix    
    if cal_confusion_matrix == True:
        print(confusion_matrix(test_y_test, y_test_predicted, labels=labelslist))
        cm_report = confusion_matrix(test_y_test, y_test_predicted, labels=labelslist, normalize=None)
        sns.set(font_scale=0.35)
        sns.heatmap(pd.DataFrame(cm_report).iloc[:, :].T, annot = True, fmt=".4g", cmap = "Blues")        
        svgoutput_path = os.path.join(outputpath+'/'+dir_name+'/'+ svg_title+'.'+'confusion_matrix'+'.'+classifier +'.svg')
        if title_ctrl == True:
            plt.title(result_title)
        plt.savefig(svgoutput_path, format='svg')
        if show_ctrl  == True:
            plt.show()
        plt.clf()
    
    #classification_report
    print(classification_report(test_y_test, y_test_predicted, labels=labelslist, target_names=targetnameslist, digits = 4))
    clf_report = classification_report(test_y_test, y_test_predicted, labels=labelslist, target_names=targetnameslist, digits = 4, output_dict = True)
    mask=pd.DataFrame(clf_report).iloc[:, :].T

    #????????????
    sns.set(font_scale=0.5)
    #nocolor[row, column]
    mask3 = mask.copy()
    mask3.iloc[:-3, :] = float('nan')
    sns.heatmap(mask3, annot=True, fmt=".4g", cmap="binary", cbar=False)
    mask2 = mask.copy()
    mask2.iloc[:, :-1] = float('nan')
    mask2.iloc[-3:, :] = float('nan')
    sns.heatmap(mask2, annot=True, fmt=".4g", cmap="Oranges")
    mask1 = mask.copy()
    mask1.iloc[:, -1] = float('nan')
    mask1.iloc[-3:, :] = float('nan')
    sns.heatmap(mask1, annot=True, fmt=".4g", cmap="Blues")
    svgoutput_path = os.path.join(outputpath+'/'+dir_name+'/' + svg_title+'.'+'classification_report'+'.'+'.'+classifier + '.svg')

    if title_ctrl == True:
        plt.title(result_title)
    plt.savefig(svgoutput_path, format='svg')
    if show_ctrl  == True:
        plt.show()
    plt.clf()

def save_models(clf, classifier):
    patht, titlet = file_timestamp()
    dir_name = "models"
    if not os.path.exists(dir_name):
        os.makedirs(dir_name)
    skloutput_path = os.path.join(outputpath+'/'+
                                  dir_name+'/' +
                                  choice_dataset+' ' +
                                  classifier+' ' +
                                  'choice_random='+str(choice_random)+' ' +
                                  'train_size='+str(train_size)+' ' +
                                  'test_size='+str(test_size)+' ' +
                                  'choice_split='+str(choice_split)+' ' +
                                  'choice_train='+str(choice_train)+' ' +
                                  patht +
                                  '.pkl')
    joblib.dump(clf, skloutput_path)

def print_tree(clf, classifier):

    if cal_tree_structure == True:   
        """
        sklearn example Tree structure
        """
        n_nodes = clf.tree_.node_count
        children_left = clf.tree_.children_left
        children_right = clf.tree_.children_right
        feature = clf.tree_.feature
        threshold = clf.tree_.threshold

        node_depth = np.zeros(shape = n_nodes, dtype = np.int64)
        is_leaves = np.zeros(shape = n_nodes, dtype = bool)
        stack = [(0, 0)]  # start with the root node id (0) and its depth (0)
        while len(stack) > 0:
            # `pop` ensures each node is only visited once
            node_id, depth = stack.pop()
            node_depth[node_id] = depth

            # If the left and right child of a node is not the same we have a split
            # node
            is_split_node = children_left[node_id] != children_right[node_id]
            # If a split node, append left and right children and depth to `stack`
            # so we can loop through them
            if is_split_node:
                stack.append((children_left[node_id], depth + 1))
                stack.append((children_right[node_id], depth + 1))
            else:
                is_leaves[node_id] = True

        print("The binary tree structure has {n} nodes and has "
            "the following tree structure:\n".format(n = n_nodes))
        for i in range(n_nodes):
            if is_leaves[i]:
                print("{space}node = {node} is a leaf node.".format(
                    space = node_depth[i] * "\t", node = i))
            else:
                print("{space}node = {node} is a split node: "
                    "go to node {left} if X[:, {feature}] <= {threshold} "
                    "else to node {right}.".format(
                        space = node_depth[i] * "\t", 
                        node = i, 
                        left = children_left[i], 
                        feature = feature[i], 
                        threshold = threshold[i], 
                        right = children_right[i]))
        """
        We can compare the above output to the plot of the decision tree.
        END example
        """

    patht, titlet = file_timestamp()    
    dir_name = "results"
    if not os.path.exists(dir_name):
        os.makedirs(dir_name)
    svg_title = patht
    svgoutput_path = os.path.join(outputpath+'/'+dir_name+'/'+ svg_title+'.'+'plottree'+'.'+'.'+classifier +'.svg')
    result_title = titlet
    result_title = classifier+'\n'+trainpath+'\n'+result_title
    dot_data = export_graphviz(clf, 
                               out_file=None, 
                               feature_names=headerdict, 
                               filled=True, 
                               rounded=True)
    pydot_graph = pydotplus.graph_from_dot_data(dot_data)
    #pydot_graph.set_size('"100, 100!"') #png
    pydot_graph.write_svg(svgoutput_path)


def main():
    if trainpath[(len('.csv')*-1):] == '.csv':
        #read
        print('read csv...', end='')
        ttt = sklearn_class(trainpath, testpath)
        print('done')
        #train
        print('read train...', end='')
        ttt.input_train_csv()
        ttt.train_numpy_csv()
        print('done')
        #test
        if choice_train == 3:
            print('read test...', end='')
            ttt.input_test_csv()
            ttt.test_numpy_csv()
            print('done')

    elif trainpath[(len('.parquet')*-1):] == '.parquet':
        #read
        print('read parquet...', end='')
        ttt = sklearn_class(trainpath, testpath)
        print('done')
        #train
        print('read train...', end='')
        ttt.input_train_parquet()
        ttt.train_numpy_parquet()
        print('done')
        #test
        if choice_train == 3:
            print('read test...', end='')
            ttt.input_test_parquet()
            ttt.test_numpy_parquet()
            print('done')

    
    print('training...', end = '\n')
    if choice_train == 1:
        #????????????
        X_train, y_train, X_test, y_test = ttt.train_X_train, ttt.train_y_train, ttt.train_X_train, ttt.train_y_train
    elif choice_train == 2:
        #???train, test
        X_train, y_train, X_test, y_test = ttt.train_X_train, ttt.train_y_train, ttt.train_X_test, ttt.train_y_test
    elif choice_train == 3:
        #??????train, test
        X_train, y_train, X_test, y_test = ttt.train_X_train, ttt.train_y_train, ttt.test_X_test, ttt.test_y_test
    else:
        print('choice_train gg')
    
    if choice_classfier == 1:
        y_test_predicted, classifier = classifier_clf(X_train, y_train, X_test)
    elif choice_classfier == 2:
        y_test_predicted, classifier = classifier_forest(X_train, y_train, X_test)
    elif choice_classfier == 3:
        y_test_predicted, classifier = classifier_svc(X_train, y_train, X_test)
    elif choice_classfier == 4:
        y_test_predicted, classifier = classifier_c45clf(X_train, y_train, X_test)
    elif choice_classfier == 5:
        y_test_predicted, classifier = classifier_clfe(X_train, y_train, X_test)
    elif choice_classfier == 6:
        y_test_predicted, classifier = classifier_lightgbm(X_train, y_train, X_test)
    elif choice_classfier == 9:
        #??????Model
        readclf = joblib.load(valid_modelpath)
        y_test_predicted, classifier = classifier_valid(readclf, X_test)
    else:
        print('choice_classfier gg')

    if choice_classfier:
        print_result(y_test, y_test_predicted, classifier)
    print('\n', '================ We Can Only See A Short Distance Ahead. ================', '\n')  

if __name__ == '__main__':
    choice_dataset = 'ipandport' 
    trainpath, testpath, headerdict = dataset_path(choice_dataset)
    for i in range(3):
        main()
    choice_dataset = 'headerfield' 
    trainpath, testpath, headerdict = dataset_path(choice_dataset)
    for i in range(3):
        main()
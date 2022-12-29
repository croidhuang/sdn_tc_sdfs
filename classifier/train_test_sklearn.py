import os
import copy
import utils
import preprocessing_dictforprint

"""
分類相關參數
"""

#要驗證的模型
try:
    valid_modelpath = './models/b255v6 RandomForest choice_random_perfile=0.004 train_size=0.8 test_size=0.2 choice_split=3 choice_train=2 1630563027.216647.pkl'
except:
    print("no model file, please check")

#輸出目錄
outputpath = './'

#輸入dataset
choice_dataset = 'b255v6'
"""
#記得改路徑字串，該資料夾所有，*.parquet或*.csv
"""
def dataset_path(choice_dataset):
    if choice_dataset == 'b255v6':
        trainpath = './preprocess/b255v6/*.parquet'
        testpath = './preprocess/b255v6/*.parquet'
        headerdict = preprocessing_dictforprint.b255dict
    elif choice_dataset == 'ipandport':
        trainpath = './preprocess/ipandport/*.parquet'
        testpath = './preprocess/ipandport/*.parquet'
        headerdict = preprocessing_dictforprint.ipandport_dict
    elif choice_dataset == 'headerfield':
        trainpath = './preprocess/headerfield/*.parquet'
        testpath = './preprocess/headerfield/*.parquet'
        headerdict = preprocessing_dictforprint.headerfield_dict
    else:
        print("choice_dataset gg")

    return trainpath, testpath, headerdict

trainpath, testpath, headerdict = dataset_path(choice_dataset)

#最後要分類什麼，label要什麼
#'app'
#'traffic'
class_id = 'app'

#choice_random_perfile每個pcap取幾個或取比例, 注意0是比例全部(1是1個非比例1), b255一個檔案10, 000, 全部11, 000, 000記憶體可能GG
#最少的是AIM只有6個，所以最少一類就是大約choice_random_perfile*6
choice_random_perfile = 1500
#每一類加起來取幾個
total_sample_perclass = 3300
min_qty_threshold = 100 #min_qty是最低取的數量, replace是數量不足能不能重複取
randomreplace = 'False'
#size指的是取的比例, 1跟0是原地考照
train_size = 0.8
test_size = 0.2

#1原地考照
#2train_test_split same rate "all class"
#3RandomUnderSampler resample to "min(all class)"
#4StratifiedShuffleSplit same rate "each class"
choice_split = 3

#1原地考照(train就是test，看數量參數有沒有足夠train好)
#2同train, test
#3不同train, test
choice_train = 2

#1 不切
#2 一組切十次相異實驗
#3 fold cross valid
choice_valid = 1

#要不要印出來看
show_ctrl = False
#要不要標題，不然存一堆會不知道誰是誰
title_ctrl = True
#要不要計算跟存混淆矩陣
cal_confusion_matrix = True
#要不要計算跟存決策樹(要是樹的才能產生)
cal_tree_structure = False

#換分類改這個，lightgbm也差不多威
# 1clf
# 2forest
# 3svc
# 4c45clf
# 5clfe
# 6lightgbm
# 9valid
choice_classfier = 2

strrecord = ''

"""
##################################################################################
"""

#sklearn的切set工具要numpy
import numpy as np
#處理parquet讀跟選column
import pandas as pd
#轉datatype csv的list字串變float
from ast import literal_eval
import ast
#用來mergeparquet
import glob as glob

#畫圖
from matplotlib import pyplot as plt
#畫結果heatmap上色
import seaborn as sns
import itertools
#圖壓時間
from datetime import datetime, timezone, timedelta

#畫decision tree
import pydotplus
from sklearn.tree import export_graphviz
#存model
import joblib

from sklearn.model_selection import train_test_split, StratifiedShuffleSplit, StratifiedKFold
from sklearn.tree import DecisionTreeClassifier
from sklearn.svm import SVC
from sklearn import tree, ensemble
from sklearn.metrics import classification_report, confusion_matrix

#平衡取data
#https://imbalanced-learn.org/stable/
from imblearn.under_sampling import RandomUnderSampler

#RaczeQ的decision tree c4.5
#https://github.com/RaczeQ/scikit-learn-C4.5-tree-classifier
from c45RaczeQ.c45 import C45

#LightGBM的sklearn風格
#https://lightgbm.readthedocs.io/en/latest/
import lightgbm

#weka
import os
import traceback


"""
#算照比例每個是多少個的函數
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
dataset主要用的class
"""
class sklearn_class:
    def __init__(self, trainpath, testpath):
        self.trainpath = trainpath
        self.testpath = testpath
        self.train_glob_merged_data = []
        self.test_glob_merged_data = []
        if class_id == 'traffic':
            self.class_label = 'traffic_label'
            self.class_total = len(utils.ID_TO_TRAFFIC)
            self.class_dict = utils.ID_TO_TRAFFIC
        elif class_id == 'app':
            self.class_label = 'app_label'
            self.class_total = len(utils.ID_TO_APP)
            self.class_dict = utils.ID_TO_APP

    def input_func(self, dataset_id, file_id):
        #merge多個
        if dataset_id == 'train':
            glob_files = glob.glob(self.trainpath)
        elif dataset_id == 'test':
            glob_files = glob.glob(self.testpath)
        else:
            print('dataset_id gg')

        #用來收抽取的資料
        glob_app_data = {i:[] for i in range(self.class_total)}
        glob_app_data[99]=[]
        glob_app_data['NaN']=[]
        #載入個別檔案並抽取到上面兩個list
        for f in glob_files:
            reader = []
            if file_id == 'csv':
                reader = pd.read_csv(f, engine='c')                
            elif file_id == 'parquet':
                reader = pd.read_parquet(f, engine='fastparquet')
            else:
                print('file_id gg')

            """
            決定取幾個
            """
            #如果是0就全部
            if choice_random_perfile == 0:
                pass
            else:
                len_index = len(reader.index)
                #如果是整數取整數
                if isinstance(choice_random_perfile, int):
                    min_qty = int(choice_random_perfile)
                #如果是分數取比例
                else:
                    min_qty = int(len_index*choice_random_perfile)

                #最小值
                if min_qty-min_qty_threshold <= 0:
                    min_qty = min_qty_threshold
                #最大值
                if min_qty > len_index:
                    min_qty = len_index
                    ###print(dataset_id,f, min_qty)

                reader = reader.sample(n=min_qty, replace=randomreplace)
                try:
                    glob_app_data[int(reader[self.class_label].values[0])].append(reader)
                except:
                    print(int(reader[self.class_label].values[0]))
                    
        glob_data=[]
        for d in glob_app_data.values():
            for dd in d:
                glob_data.append(dd)
        #轉pd
        glob_merged_data = pd.concat(glob_data, ignore_index=True)
        if dataset_id == 'train':
            self.train_glob_merged_data = glob_merged_data
        elif dataset_id == 'test':
            self.test_glob_merged_data = glob_merged_data
        else:
            print('dataset_id gg')
        #可印整個大檔會簡略顯示
        #print(glob_merged_data)

    def input_train_csv(self):
        #merge多個csv
        self.input_func(dataset_id='train', file_id='csv')

    def input_train_parquet(self):
        #merge多個parquet
        self.input_func(dataset_id='train', file_id='parquet')

    def input_test_csv(self):
        self.input_func(dataset_id='test', file_id='csv')

    def input_test_parquet(self):
        self.input_func(dataset_id='test', file_id='parquet')

    def get_dataset(self, dataset_id, file_id):
        #轉到numpy因為sklearn要用
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
        y = glob_merged_data[self.class_label].values.reshape(-1,).tolist()
        y = np.array(y)
        #沒事別印會印到細節GG
        #print(X, y)

        return X, y

    def split_numpy_func(self, X, y, dataset_id, file_id):
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
            under_train = RandomUnderSampler(sampling_strategy = {int(samr):int(total_sample_perclass*train_size) for samr in range(self.class_total)}, random_state=0)
            X_train, y_train = under_train.fit_resample(under_X_train, under_y_train)
            under_test = RandomUnderSampler(sampling_strategy = {int(samr):int(total_sample_perclass*test_size) for samr in range(self.class_total)}, random_state=0)
            X_test, y_test = under_test.fit_resample(under_X_test, under_y_test)
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
        #trainset多個csv
        X,y = self.get_dataset(dataset_id='train', file_id='csv')
        self.split_numpy_func(X, y, dataset_id='train', file_id='csv')

    def train_numpy_parquet(self):
        #trainset多個parquet
        X,y = self.get_dataset(dataset_id='train', file_id='parquet')
        self.split_numpy_func(X, y, dataset_id='train', file_id='parquet')

    def test_numpy_csv(self):
        X,y = self.get_dataset(dataset_id='test', file_id='csv')
        self.split_numpy_func(X, y, dataset_id='test', file_id='csv')

    def test_numpy_parquet(self):
        X,y = self.get_dataset(dataset_id='test', file_id='parquet')
        self.split_numpy_func(X, y, dataset_id='test', file_id='parquet')


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
    forest = ensemble.RandomForestClassifier(n_estimators=512, criterion="entropy", class_weight="balanced")
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


def print_result(test_y_test, y_test_predicted, class_dict, classifier):
    #print(test_y_test, y_test_predicted)
    
    labelslist = []
    targetnameslist = []
    for k, v in class_dict.items():
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
    strrecord = classification_report(test_y_test, y_test_predicted, labels=labelslist, target_names=targetnameslist, digits = 4)
    dictrecord = clf_report

    #分區著色
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
    return cm_report,dictrecord

def print_text_report(inputrecord):                                          
    longest_last_line_heading = "weighted avg"
    name_width = max(len(k) for k,v in inputrecord.items())
    width = max(name_width, len(longest_last_line_heading))
    digits = 4

    headers = ["precision", "recall", "f1-score", "support"]
    head_fmt = "{:>{width}s} " + " {:>9}" * len(headers)
    report = head_fmt.format("", *headers, width=width)
    report += "\n\n"          
    
    rows=[[] for row in range(len(inputrecord.keys()))]
    ri=0
    for k,v in inputrecord.items():
        rows[ri].append(str(k))
        if isinstance(v,dict):
            for vv in v.values():
                rows[ri].append(vv)
        else:
            rows[ri].append(v)
        ri+=1
    row_fmt = "{:>{width}s} " + " {:>9.{digits}f}" * 3 + " {:>9}\n"
    row_fmt_accuracy = ("{:>{width}s} " + " {:>9.{digits}}" * 2 + " {:>9.{digits}f}" + " {:>9}\n")
    for row in rows:
        if row[0] == "accuracy":                
            report += row_fmt_accuracy.format(row[0], "", "", row[1],"", width=width, digits=digits)
        else:                    
            report += row_fmt.format(*row, width=width, digits=digits)
    return report

def print_fold_cmreport(inputcmreport):  
    cmreport = ''
    digits = 4
    col = len(inputcmreport[0])
    for row in inputcmreport:        
        row_fmt = ("{:>9.{digits}f}" * col+"\n")
        cmreport += row_fmt.format(*row, digits=digits)
    return cmreport

def save_models(clf, classifier):
    """
    patht, titlet = file_timestamp()
    dir_name = "models"
    if not os.path.exists(dir_name):
        os.makedirs(dir_name)
    skloutput_path = os.path.join(outputpath+'/'+
                                  dir_name+'/' +
                                  choice_dataset+' ' +
                                  classifier+' ' +
                                  'choice_random_perfile='+str(choice_random_perfile)+' ' +
                                  'train_size='+str(train_size)+' ' +
                                  'test_size='+str(test_size)+' ' +
                                  'choice_split='+str(choice_split)+' ' +
                                  'choice_train='+str(choice_train)+' ' +
                                  patht +
                                  '.pkl')
    joblib.dump(clf, skloutput_path)
    """
    return None

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


def choice_classfier_func(X_train, y_train, X_test):
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
        #讀取Model
        readclf = joblib.load(valid_modelpath)
        y_test_predicted, classifier = classifier_valid(readclf, X_test)
    else:
        print('choice_classfier gg')

    print('\n', '================ We Can Only See A Short Distance Ahead. ================', '\n')
    return y_test_predicted, classifier 



def ten_time_avg(ttt, X_train, y_train, X_test, y_test):
    train_skf = StratifiedKFold(n_splits=10)
    train_skf.get_n_splits(X_train, y_train)
    test_skf = StratifiedKFold(n_splits=10)
    test_skf.get_n_splits(X_test, y_test)

    sum_dictrecord={}
    sum_cm_report=[]

    for i in range(10):
        train_index = list(train_skf.split(X_train, y_train))[i][1]
        test_index = list(test_skf.split(X_test, y_test))[i][1]
        X_train_times, y_train_times, X_test_times, y_test_times = X_train[train_index], y_train[train_index], X_test[test_index], y_test[test_index]

        y_test_predicted, classifier = choice_classfier_func(X_train_times, y_train_times, X_test_times)

        if choice_classfier:
            cmrecord,dictrecord = print_result(y_test_times, y_test_predicted, ttt.class_dict, classifier)
        
        #sum 1~10
        for dictk,dictv in dictrecord.items():
            if not dictk in sum_dictrecord.keys():
                sum_dictrecord[dictk]=dictv
            else:
                if isinstance(dictv,dict):
                    for k,v in dictv.items():
                        sum_dictrecord[dictk][k]+=dictrecord[dictk][k]
                else:
                    sum_dictrecord[dictk]+=dictrecord[dictk]
        
        if sum_cm_report == []:
            sum_cm_report = [[] for cmi,cmlist in enumerate(cmrecord)]
            for cmi,cmlist in enumerate(cmrecord):
                for cmii, cmitem in enumerate(cmlist):
                    sum_cm_report[cmi].append(cmitem)
        else:
            for cmi,cmlist in enumerate(cmrecord):
                for cmii, cmitem in enumerate(cmlist):
                    sum_cm_report[cmi][cmii] += cmitem

        
        report = f'{i}-time\n'
        report += print_text_report(dictrecord)
        cm_report = print_fold_cmreport(cmrecord)
        """
        txtoutput_path = os.path.join(outputpath+'/'+"results"+'/'+ choice_dataset +'.txt')
        f = open(txtoutput_path , 'a')
        f.write(cm_report)
        f.write(report)
        f.write('\n')
        f.close()
        """

        #10 cal avg
        if i == (10-1):
            for k,v in sum_dictrecord.items():
                if isinstance(v,dict):
                    for kk,vv in v.items():
                        if isinstance(vv,float):
                            sum_dictrecord[k][kk]=sum_dictrecord[k][kk]/10
                        else:
                            sum_dictrecord[k][kk]=int(sum_dictrecord[k][kk]/10)
                else:
                    sum_dictrecord[k]=sum_dictrecord[k]/10 

            for cmi,cmlist in enumerate(sum_cm_report):
                for cmii, cmitem in enumerate(cmlist):
                    sum_cm_report[cmi][cmii] = float(sum_cm_report[cmi][cmii]/10)

            
            cm_report = '========10-time avg========\n'
            cm_report += print_fold_cmreport(sum_cm_report)
            report='========10-time avg========\n'
            report += print_text_report(sum_dictrecord)
            txtoutput_path = os.path.join(outputpath+'/'+"results"+'/'+ choice_dataset +'.txt')
            f = open(txtoutput_path , 'a')
            f.write(cm_report)
            f.write(report)
            f.write('\n')
            f.close()


def ten_foldcross(ttt, X_train, y_train, X_test, y_test):
    
    X_merge = np.concatenate((X_train , X_test), axis=0)
    y_merge = np.concatenate((y_train , y_test), axis=0)

    merge_skf = StratifiedKFold(n_splits=10)
    merge_skf.get_n_splits(X_merge, y_merge)

    sum_dictrecord={}
    sum_cm_report=[]

    for i in range(10):

        for ki,(train_i,test_i) in enumerate(merge_skf.split(X_merge, y_merge)):
            if ki != i:
                try:
                    train_index = np.concatenate((train_index , train_i), axis=0)
                except:
                    train_index = train_i
            else:
                try:
                    test_index = np.concatenate((test_index , test_i), axis=0)
                except:
                    test_index = test_i               

        train_index = list(train_index)
        test_index = list(test_index)
        X_train_foldcross, y_train_foldcross, X_test_foldcross, y_test_foldcross = X_merge[train_index], y_merge[train_index], X_merge[test_index], y_merge[test_index]

        y_test_predicted, classifier = choice_classfier_func(X_train_foldcross, y_train_foldcross, X_test_foldcross)

        if choice_classfier:
            cmrecord,dictrecord = print_result(y_test_foldcross, y_test_predicted, ttt.class_dict, classifier)
        
        #sum 1~10
        for dictk,dictv in dictrecord.items():
            if not dictk in sum_dictrecord.keys():
                sum_dictrecord[dictk]=dictv
            else:
                if isinstance(dictv,dict):
                    for k,v in dictv.items():
                        sum_dictrecord[dictk][k]+=dictrecord[dictk][k]
                else:
                    sum_dictrecord[dictk]+=dictrecord[dictk]
        
        if sum_cm_report == []:
            sum_cm_report = [[] for cmi,cmlist in enumerate(cmrecord)]
            for cmi,cmlist in enumerate(cmrecord):
                for cmii, cmitem in enumerate(cmlist):
                    sum_cm_report[cmi].append(cmitem)
        else:
            for cmi,cmlist in enumerate(cmrecord):
                for cmii, cmitem in enumerate(cmlist):
                    sum_cm_report[cmi][cmii] += cmitem
        
        report = f'{i}-foldcross\n'
        report += print_text_report(dictrecord)
        cm_report = print_fold_cmreport(cmrecord)
        """
        txtoutput_path = os.path.join(outputpath+'/'+"results"+'/'+ choice_dataset +'.txt')
        f = open(txtoutput_path , 'a')
        f.write(cm_report)
        f.write(report)
        f.write('\n')
        f.close()
        """

        #10 cal avg
        if i == (10-1):
            for k,v in sum_dictrecord.items():
                if isinstance(v,dict):
                    for kk,vv in v.items():
                        if isinstance(vv,float):
                            sum_dictrecord[k][kk]=sum_dictrecord[k][kk]/10
                        else:
                            sum_dictrecord[k][kk]=int(sum_dictrecord[k][kk]/10)
                else:
                    sum_dictrecord[k]=sum_dictrecord[k]/10 

            for cmi,cmlist in enumerate(sum_cm_report):
                for cmii, cmitem in enumerate(cmlist):
                    sum_cm_report[cmi][cmii] = float(sum_cm_report[cmi][cmii]/10)

            
            cm_report = '========10-foldcross avg========\n'
            cm_report += print_fold_cmreport(sum_cm_report)
            report='========10-foldcross avg========\n'
            report += print_text_report(sum_dictrecord)
            txtoutput_path = os.path.join(outputpath+'/'+"results"+'/'+ choice_dataset +'.txt')
            f = open(txtoutput_path , 'a')
            f.write(cm_report)
            f.write(report)
            f.write('\n')
            f.close()

def one8020(ttt, X_train, y_train, X_test, y_test):
    y_test_predicted, classifier = choice_classfier_func(X_train, y_train, X_test)    
    if choice_classfier:
        cmrecord,dictrecord = print_result(y_test, y_test_predicted, ttt.class_dict, classifier)
    report = f'8020 \n'
    report += print_text_report(dictrecord)
    cm_report = print_fold_cmreport(cmrecord)
    txtoutput_path = os.path.join(outputpath+'/'+"results"+'/'+ choice_dataset +'.txt')
    f = open(txtoutput_path , 'a')
    f.write(cm_report)
    f.write(report)
    f.write('\n')
    f.close()

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
        #原地考照
        X_train, y_train, X_test, y_test = ttt.train_X_train, ttt.train_y_train, ttt.train_X_train, ttt.train_y_train
    elif choice_train == 2:
        #同train, test
        X_train, y_train, X_test, y_test = ttt.train_X_train, ttt.train_y_train, ttt.train_X_test, ttt.train_y_test
    elif choice_train == 3:
        #不同train, test
        X_train, y_train, X_test, y_test = ttt.train_X_train, ttt.train_y_train, ttt.test_X_test, ttt.test_y_test
    else:
        print('choice_train gg')

    #one8020
    one8020(ttt, X_train, y_train, X_test, y_test)
    

    #ten_time_avg(ttt, X_train, y_train, X_test, y_test)
    
    #還沒改好index會出錯
    ten_foldcross(ttt, X_train, y_train, X_test, y_test)


if __name__ == '__main__':

    class_id = 'app'
    choice_random_perfile = 1500
    total_sample_perclass = 3300

    choice_dataset = 'ipandport'
    trainpath, testpath, headerdict = dataset_path(choice_dataset)
    for i in range(1):
        main()
    choice_dataset = 'b255v6'
    trainpath, testpath, headerdict = dataset_path(choice_dataset)
    for i in range(1):
        main()
    choice_dataset = 'headerfield'
    trainpath, testpath, headerdict = dataset_path(choice_dataset)
    for i in range(1):
        main()

    class_id = 'traffic'
    choice_random_perfile = 1000
    total_sample_perclass = 3300
    choice_dataset = 'ipandport'
    trainpath, testpath, headerdict = dataset_path(choice_dataset)
    for i in range(1):
        main()
    choice_dataset = 'b255v6'
    trainpath, testpath, headerdict = dataset_path(choice_dataset)
    for i in range(1):
        main()
    choice_dataset = 'headerfield'
    trainpath, testpath, headerdict = dataset_path(choice_dataset)
    for i in range(1):
        main()

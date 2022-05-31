import operator
from random import choice

import sys
sys.path.insert(1, './')
from exp_config.exp_config import ONE_PKT_SIZE, INNTER_ARRIVAL_TIME, EST_SLICE_ONE_PKT, topo_SLICENDICT

SliceDict = topo_SLICENDICT
SliceNum = len(SliceDict)

latency_statistic = INNTER_ARRIVAL_TIME
bandpktsize_one_statistic = ONE_PKT_SIZE

bandpktsize_statistic = {}
for i in bandpktsize_one_statistic:
    bandpktsize_statistic[i] = bandpktsize_one_statistic[i] / latency_statistic[i]

latency_s_normalize = {}
bandpktsize_s_normalize = {}

latency_dynamic = {}
bandfree_dynamic = {}
latency_d_normalize = {}
bandfree_d_normalize = {}

flow_d_normalize = {}

timeout_s_normalize = {}


#normalize
def normalize_statistic(inputdict, normalizetype, best, worst):
    for k, v in inputdict.items():
        if v < 0:
            v = 0

    max_value = max(inputdict.items(), key=operator.itemgetter(1))[1]
    min_value = min(inputdict.items(), key=operator.itemgetter(1))[1]

    scale_value = abs(max_value - min_value)
    if scale_value == 0:
        scale_value = 1
    outputdict = {}
    for k, v in inputdict.items():
        if normalizetype == "latency":
            outputdict[k] = (v - min_value) / scale_value * (worst - best) + best
        elif normalizetype == "timeout":
            outputdict[k] = int((v - min_value) / scale_value * (worst - best) + best)
        else:
            outputdict[k] = (max_value - v) / scale_value * (worst - best) + best
    return outputdict


def normalize_dynamic(inputdict, statistic, normalizetype, best, worst):

    for k, v in inputdict.items():
        if v < 0:
            v = 0

    if normalizetype == "latency":
        max_value = max(inputdict.items(), key=operator.itemgetter(1))[1]
        min_value = min(statistic.items(), key=operator.itemgetter(1))[1]
    else:
        max_value = max(statistic.items(), key=operator.itemgetter(1))[1]
        min_value = min(inputdict.items(), key=operator.itemgetter(1))[1]

    scale_value = abs(max_value - min_value)
    if scale_value == 0:
        scale_value = 1

    outputdict = {}
    for k, v in inputdict.items():
        if normalizetype == "latency":
            if v <= min_value:
                outputdict[k] = best
            else:
                outputdict[k] = (v - min_value) / scale_value * (worst - best) + best
        else:
            if v >= max_value:
                outputdict[k] = best
            else:
                outputdict[k] = (max_value - v) / scale_value * (worst - best) + best

    return outputdict


def scheduler_hard_timeout(best, worst):
    latency_s_normalize = normalize_statistic(latency_statistic, "latency", 0, 1)
    bandpktsize_s_normalize = normalize_statistic(bandpktsize_statistic, "bandfree", 0, 1)

    require = weighted_require(latency_s_normalize, bandpktsize_s_normalize, flow_d_normalize)
    timeout_s_normalize = normalize_statistic(dict(require), "timeout", best, worst)
    return timeout_s_normalize


#algo
def weighted_require(latency_s_normalize, bandpktsize_s_normalize, flow_s_normalize):
    r = {}

    for i in range(SliceNum):
        try:
            r[i] = latency_s_normalize[i] + bandpktsize_s_normalize[i] + flow_s_normalize[i]
        except:
            r[i] = 1 + 1 + 1

    r = sorted(r.items(), key=lambda item: item[1])

    return r


def weighted_quality(latency_s_normalize, bandpktsize_s_normalize, latency_d_normalize, bandfree_d_normalize):
    q = {}

    for i in range(SliceNum):
        try:
            q[i] = (latency_s_normalize[i] * latency_d_normalize[i]) + (bandpktsize_s_normalize[i] * bandfree_d_normalize[i])
        except:
            q[i] = 1 + 1

    q = sorted(q.items(), key=lambda item: item[1])

    return q


def binary_search(arr, low, high, x):
    if high >= low:
        mid = (high + low) // 2
        if arr[mid] == x:
            return mid
        elif arr[mid] > x:
            return binary_search(arr, low, mid - 1, x)
        else:
            return binary_search(arr, mid + 1, high, x)
    else:
        return -1


def scheduler_algo(class_result, latency, bandfree, flow):
    if class_result == -1:
        return class_result
    try:
        latency_s_normalize = normalize_statistic(latency_statistic, "latency", 0, 1)
        bandpktsize_s_normalize = normalize_statistic(bandpktsize_statistic, "bandfree", 0, 1)

        latency_d_normalize = normalize_dynamic(latency, latency_statistic, "latency", 0, 1)
        bandfree_d_normalize = normalize_dynamic(bandfree, bandpktsize_statistic, "bandfree", 0, 1)
        flow_d_normalize = normalize_statistic(flow, "flow", 0, 1)

        require = weighted_require(latency_s_normalize,bandpktsize_s_normalize, flow_d_normalize)
        quality = weighted_quality(latency_s_normalize,bandpktsize_s_normalize,latency_d_normalize, bandfree_d_normalize)

        #sort,(key, value)
        for i, r in enumerate(require):
            if r[0] == class_result:
                nstlarge_require = i

        if nstlarge_require == 0:
            slice_num = quality[0][0]
        elif nstlarge_require > 0 and nstlarge_require < (len(require) - 1):
            slice_num = quality[1][0]
        elif nstlarge_require == (len(require) - 1):
            slice_num = quality[-1][0]

        return slice_num

    except:
        return class_result


def random_algo(class_result, latency, bandfree, flow):
    outputlist = [(i, bandfree[i]) for i in range(SliceNum)]
    avgroup = []
    
    for i in range(len(outputlist)):
        av_slice_num = outputlist[i][0]
        av = outputlist[i][1]
        if av >= EST_SLICE_ONE_PKT[class_result]:
            avgroup.append(av_slice_num)

    if avgroup:
        slice_num = choice(avgroup)
    else:
        slice_num = class_result

    return slice_num


def MAX_algo(class_result, latency, bandfree, flow):
    outputdict = {i: bandfree[i] for i in range(SliceNum)}
    sortgroup = sorted(outputdict.items(),key=lambda item: item[1],reverse=True)
        
    for i in range(len(sortgroup)):        
        av_slice_num = sortgroup[i][0]
        av = sortgroup[i][1]
        if av > 0 and av - EST_SLICE_ONE_PKT[class_result] >= 0:
            max_value = sortgroup[i][1]
            break

    avgroup = []
    for i in range(len(sortgroup)):
        av_slice_num = sortgroup[i][0]
        av = sortgroup[i][1]
        if av - EST_SLICE_ONE_PKT[class_result] >= 0 and av == max_value:
            avgroup.append(av_slice_num)

    if avgroup:        
        slice_num = choice(avgroup)
    else:
        slice_num = class_result

    return slice_num


def min_algo(class_result, latency, bandfree, flow):
    outputdict = {i: bandfree[i] for i in range(SliceNum)}
    sortgroup = sorted(outputdict.items(), key=lambda item: item[1])

    for i in range(len(sortgroup)):
        av_slice_num = sortgroup[i][0]
        av = sortgroup[i][1]
        if av > 0 and av >= EST_SLICE_ONE_PKT[class_result]:
            min_value = sortgroup[i][1]
            break

    avgroup = []
    for i in range(len(sortgroup)):
        av_slice_num = sortgroup[i][0]
        av = sortgroup[i][1]
        if av >= EST_SLICE_ONE_PKT[class_result] and av == min_value:
            avgroup.append(av_slice_num)

    if avgroup:
        slice_num = choice(avgroup)
    else:
        slice_num = class_result

    return slice_num
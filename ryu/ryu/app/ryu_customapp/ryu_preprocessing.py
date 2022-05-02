#reference
#https://github.com/munhouiani/Deep-Packet
#author munhouiani


#https://docs.python.org/3/library/pathlib.html 使路徑適合各種OS
from pathlib import Path

import numpy as np
from numpy.core.numeric import NaN
import pandas as pd

#https://joblib.readthedocs.io/en/latest/ 流程優化重用計算
from joblib import Parallel, delayed

#https://scapy.net/用來處理封包的module
from scapy.compat import raw
from scapy.layers.inet import IP, UDP, TCP
from scapy.layers.inet6 import IPv6
from scapy.layers.dns import DNS
from scapy.layers.l2 import Ether
from scapy.packet import Padding
from scapy.utils import rdpcap

#只用一次，轉成稀疏矩陣
from scipy import sparse

def should_omit_packet(packet):
    # SYN, ACK or FIN flags set to 1 and no payload
    if TCP in packet and (packet.flags & 0x13):
        # not payload or contains only padding
        layers = packet[TCP].payload.layers()
        if not layers or (Padding in layers and len(layers) == 1):
            return True

    # DNS segment
    if DNS in packet:
        return True

    return False


def remove_ether_header(packet):
    if Ether in packet:
        return packet[Ether].payload

    return packet


def mask_ip(packet):
    if IP in packet:
        packet[IP].src = '0.0.0.0'
        packet[IP].dst = '0.0.0.0'
    elif IPv6 in packet:
        packet[IPv6].src = '0:0:0:0:0:0:0:0'
        packet[IPv6].dst = '0:0:0:0:0:0:0:0'

    return packet

def mask_tcpudp(packet):
    if TCP in packet:
        packet[TCP].sport = 0
        packet[TCP].dport = 0

    if UDP in packet:
        packet[UDP].sport = 0
        packet[UDP].dport = 0
    return packet

 

def pad_udp(packet):
    if UDP in packet:
        # get layers after udp
        layer_after = packet[UDP].payload.copy()

        # build a padding layer
        pad = Padding()
        pad.load = '\x00' * 12

        layer_before = packet.copy()
        layer_before[UDP].remove_payload()
        packet = layer_before / pad / layer_after

        return packet

    return packet


def packet_to_sparse_array(packet, max_length=40):
    
    arr = np.frombuffer(raw(packet), dtype=np.uint8)[0: max_length] / 255
    if len(arr) < max_length:
        pad_width = max_length - len(arr)
        arr = np.pad(arr, pad_width=(0, pad_width), constant_values=0)
    
    arr = sparse.csr_matrix(arr)
    
    return arr


def transform_packet(packet):
    if should_omit_packet(packet):
        return None
    
    packet = remove_ether_header(packet)
    packet = mask_tcpudp(packet)
    packet = pad_udp(packet)
    packet = mask_ip(packet)
    
    arr = packet_to_sparse_array(packet)

    return arr


def transform_pcap(pcap):
    #每個pcap轉檔完路徑檔名跟附註SUCCESS

    rows = []
    try:
        packets = rdpcap(pcap)
    except:
        packets = rdpcap(str(pcap))
        
    try:
        pkt = packets[-1]
        arr = transform_packet(pkt)
    except:
        return 0
    if arr is not None:         
        row = {
            'feature': arr.todense().tolist()[0]
        }
        rows.append(row)
        df = pd.DataFrame(rows)
        X = df['feature'].values.reshape(-1,).tolist()
        X = np.array(X)
        return X

if __name__ == '__main__':
    pcap=('/home/croid/mypcap.pcap')
    transform_pcap(pcap)
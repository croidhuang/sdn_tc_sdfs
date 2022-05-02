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

#label
from utils import PREFIX_TO_APP_ID, PREFIX_TO_TRAFFIC_ID

import binascii

source="./pcap/completePCAP"
target="./pcap/ipandport"

def read_pcap(path: Path):
    packets = rdpcap(str(path))
    return packets

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
    #byte/255
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

def transform_packet_onlyipandport(packet):
    if should_omit_packet(packet):
        return None
    
    #ipv6leng 128bit=16B 0,16
    #L4port 16bit=2B 32,34
    ipandport=[0]*36

    if IP in packet:
        for i,s in enumerate(str(packet[IP].src).split(".")):
            ipandport[i] = int(s)
        for i,s in enumerate(str(packet[IP].dst).split(".")):
            ipandport[i+16] = int(s)
            
    elif IPv6 in packet:
        for ki,k in enumerate(str(packet[IPv6].src).split(":")):
            seg=str(k.zfill(4))
            seg=binascii.a2b_hex(seg)
            for si,s in enumerate(seg):
                ipandport[ki*2+si] += int(s)
        for ki,k in enumerate(str(packet[IPv6].dst).split(":")):
            seg=str(k.zfill(4))
            seg=binascii.a2b_hex(seg)
            for si,s in enumerate(seg):
                ipandport[ki*2+si+16] += int(s)

    if TCP in packet:
        portbin=str(bin(packet[TCP].sport)).lstrip('0b')
        portbin=portbin.zfill(16)
        ipandport[32]=int(portbin[:8],2)
        ipandport[33]=int(portbin[8:],2)
        portbin=str(bin(packet[TCP].dport)).lstrip('0b')
        portbin=portbin.zfill(16)
        ipandport[34]=int(portbin[:8],2)
        ipandport[35]=int(portbin[8:],2)

    if UDP in packet:
        portbin=str(bin(packet[UDP].sport)).lstrip('0b')
        portbin=portbin.zfill(16)
        ipandport[32]=int(portbin[:8],2)
        ipandport[33]=int(portbin[8:],2)
        portbin=str(bin(packet[UDP].dport)).lstrip('0b')
        portbin=portbin.zfill(16)
        ipandport[34]=int(portbin[:8],2)
        ipandport[35]=int(portbin[8:],2)

    arr = [float(int(i)/255) for i in ipandport]

    return arr

def transform_pcap(path, output_path: Path = None, output_batch_size=10000):
    #每個pcap轉檔完路徑檔名跟附註SUCCESS
    if Path(str(output_path.absolute()) + '_SUCCESS').exists():
        print(output_path, 'Done')
        return

    print('Processing', path)

    rows = []
    batch_index = 0
    for i, packet in enumerate(read_pcap(path)):
        arr = transform_packet_onlyipandport(packet)
        if arr is not None:
            # get labels for app identification
            #讀utils.py的label
            prefix = path.name.split('.')[0].lower()
            try:
                app_label = PREFIX_TO_APP_ID.get(prefix)
            except:
                app_label=99    
            try:
                traffic_label = PREFIX_TO_TRAFFIC_ID.get(prefix)
            except:
                traffic_label=99    
            
            if app_label == 'NaN':
                app_label=99
            if traffic_label == 'NaN':
                traffic_label=99
                
            row = {
                'app_label': app_label,
                'traffic_label': traffic_label,
                'feature': arr,
            }
            rows.append(row)
        
        ###pandas轉什麼檔to_檔名###
        #https://pandas.pydata.org/pandas-docs/stable/reference/api/pandas.DataFrame.html
        # write every batch_size packets, by default 10000
        
        if rows and i > 0 and i % output_batch_size == 0:
            part_output_path = Path(str(output_path.absolute()) + f'_part_{batch_index:04d}.parquet')
            df = pd.DataFrame(rows)
            df.to_parquet(part_output_path)
            batch_index += 1
            rows.clear()
        """
        if rows and i > 0 and i % output_batch_size == 0:
            part_output_path = Path(str(output_path.absolute()) + f'_part_{batch_index:04d}.csv')
            df = pd.DataFrame(rows)
            df.to_csv(part_output_path)
            batch_index += 1
            rows.clear()
        """
        
    ###pandas轉什麼檔to_檔名###
    #https://pandas.pydata.org/pandas-docs/stable/reference/api/pandas.DataFrame.html
    # final write
    
    if rows:
        df = pd.DataFrame(rows)
        part_output_path = Path(str(output_path.absolute()) + f'_part_{batch_index:04d}.parquet')
        df.to_parquet(part_output_path)
    """    
    if rows:
        df = pd.DataFrame(rows)
        part_output_path = Path(str(output_path.absolute()) + f'_part_{batch_index:04d}.csv')
        df.to_csv(part_output_path)
    """

    # write success file
    with Path(str(output_path.absolute()) + '_SUCCESS').open('w') as f:
        f.write('')

    print(output_path, 'Done')


def main(source, target):
    data_dir_path = Path(source)
    target_dir_path = Path(target)
    target_dir_path.mkdir(parents=True, exist_ok=True)
 
    for pcap_path in sorted(data_dir_path.iterdir()):
        transform_pcap(pcap_path, target_dir_path / (pcap_path.name + '.transformed')) 


if __name__ == '__main__':
    main(source, target)

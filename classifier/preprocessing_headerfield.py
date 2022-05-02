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

source="./pcap/completePCAP"
target="./pcap/headerfield"

ipv4_field_len_dict={#13
    'version':4,
    'ihl':4,
    'tos':6,
    'len':16,
    'id':16,
    'flags':3,
    'frag':13,
    'ttl':8,
    'proto':8,
    'chksum':16,
    'src':32,
    'dst':32,
    'options':288,
}
ipv6_field_len_dict={#8
    'version':4,
    'tc':8,
    'fl':20,
    'plen':16,
    'nh':8,
    'hlim':8,
    'src':128,
    'dst':128,
}
tcp_field_len_dict={#11
    'sport':16,
    'dport':16,
    'seq':32,
    'ack':32,
    'dataofs':4,
    'reserved':3,
    'flags':9,
    'window':16,
    'chksum':16,
    'urgptr':16,
    'options':32,
}
udp_field_len_dict={#4
    'sport':16,
    'dport':16,
    'len':16,
    'chksum':16,
}

headerfield_dict={
    'ipv4_version':0,
    'ipv4_ihl':1,
    'ipv4_tos':2,
    'ipv4_len':3,
    'ipv4_id':4,
    'ipv4_flags':5,
    'ipv4_frag':6,
    'ipv4_ttl':7,
    'ipv4_proto':8,
    'ipv4_chksum':9,
    'ipv4_src':10,
    'ipv4_dst':11,
    'ipv4_options':12,
    'ipv6_version':13,
    'ipv6_tc':14,
    'ipv6_fl':15,
    'ipv6_plen':16,
    'ipv6_nh':17,
    'ipv6_hlim':18,
    'ipv6_src':19,
    'ipv6_dst':20,
    'tcp_sport':21,
    'tcp_dport':22,
    'tcp_seq':23,
    'tcp_ack':24,
    'tcp_dataofs':25,
    'tcp_reserved':26,
    'tcp_flags':27,
    'tcp_window':28,
    'tcp_chksum':29,
    'tcp_urgptr':30,
    'tcp_options':31,
    'udp_sport':32,
    'udp_dport':33,
    'udp_len':34,
    'udp_chksum':35
 }


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


def transform_packet_onlyheaderfield(packet):
    if should_omit_packet(packet):
        return None

    listlen=len(ipv4_field_len_dict)+len(ipv6_field_len_dict)+len(tcp_field_len_dict)+len(udp_field_len_dict)
    headerfield=[0]*listlen
    
    packet = remove_ether_header(packet)
    packet = mask_tcpudp(packet)
    packet = mask_ip(packet)

    if IP in packet:
        for f in IP().fields_desc:
            headerfield_num = headerfield_dict['ipv4_'+f.name]
            if f.name == 'src' or f.name == 'dst':
                headerfield[headerfield_num] = 0.0
            elif f.name == 'options':
                headerfield[headerfield_num] = 0.0
            else:
                headerfield[headerfield_num] = int(packet[IP].getfieldval(f.name)) / (2**ipv4_field_len_dict[f.name])
    if IPv6 in packet:
        for f in IPv6().fields_desc:
            headerfield_num = headerfield_dict['ipv6_'+f.name]
            if f.name == 'src' or f.name == 'dst':
                headerfield[headerfield_num] = 0.0
            elif f.name == 'options':
                headerfield[headerfield_num] = 0.0
            else:
                headerfield[headerfield_num] = int(packet[IPv6].getfieldval(f.name)) / (2**ipv6_field_len_dict[f.name])
    if TCP in packet:
        for f in TCP().fields_desc:
            headerfield_num = headerfield_dict['tcp_'+f.name]
            if f.name == 'options':
                headerfield[headerfield_num] = 0.0
            else:
                headerfield[headerfield_num] = int(packet[TCP].getfieldval(f.name)) / (2**tcp_field_len_dict[f.name])
    if UDP in packet:
        for f in UDP().fields_desc:
            headerfield_num = headerfield_dict['udp_'+f.name]
            headerfield[headerfield_num] = int(packet[UDP].getfieldval(f.name)) / (2**udp_field_len_dict[f.name])

    return headerfield

def transform_pcap(path, output_path: Path = None, output_batch_size=10000):
    #每個pcap轉檔完路徑檔名跟附註SUCCESS
    if Path(str(output_path.absolute()) + '_SUCCESS').exists():
        print(output_path, 'Done')
        return

    print('Processing', path)

    rows = []
    batch_index = 0
    for i, packet in enumerate(read_pcap(path)):
        arr = transform_packet_onlyheaderfield(packet)
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

import pandas as pd
import re
import numpy as np

#Return true if the values in the column are numeric
def isNumeric(column): 
    for item in column:
        if type(item) != float and type(item) != int and item != "?":
            return False   
    return True

#Return true if the values in the column are dates
def isDate(column):
    for item in column: 
        try:
            pd.to_datetime(item)
        except:
            if item != "?": 
                return False
    return True

def toARFF(df, fileName):
   
    df = df.fillna("?")

    writeFile = open(fileName, 'w')
    pattern = r"\..*"
    relation = re.sub(pattern, "", fileName)
    writeFile.write("@RELATION\t" + 'train' + "\n")
    #Check the type for each column and write them in as attributes
    for colName in list(df):
        options = set([])
        if isNumeric(df[colName]) == True:
            writeFile.write("@ATTRIBUTE\t" + colName)
            writeFile.write("\tnumeric\n")
        elif colName != 'feature':
            writeFile.write("@ATTRIBUTE\t" + colName) 
            for value in df[colName]:
                if value != "?": 
                    options.add(value)
            if len(options) == len(df[colName]):
                writeFile.write("\tstring\n")
            else:
                writeFile.write("\t{")
                writeFile.write(str(options.pop()))
                for o in options:
                    writeFile.write("," + str(o))
                writeFile.write("}\n")
        else:
            headerdict={
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
            for i in range(1,40):
                fcolname=str(headerdict[i])
                writeFile.write("@ATTRIBUTE\t"+fcolname)
                writeFile.write("\tNUMERIC\n")


#Write out the data
#If there's a space in the value, surround it with quotes
    writeFile.write("@DATA\n")
    for line in df.values:
        writeFile.write(str(line[0]))
        for i in range(1, len(line)):
            if i==2:
                for j in line[i]:
                    writeFile.write("," + str(j))
            else:
                writeFile.write("," + str(line[i])) 
        writeFile.write("\n")
 
 
    writeFile.close() 
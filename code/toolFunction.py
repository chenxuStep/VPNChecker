import os
import re
import yaml
import struct
import socket
import pandas as pd
from collections import Counter
import ipaddress




def fileExists(readfilePath):
    if os.path.exists(readfilePath):
        return True
    else:
        return False



def readTxt(readfilePath):
    with open(readfilePath) as file:
        lines = file.readlines()
        listStr = list()
        for line in lines:
            listStr.append("".join(line.split()))

    return listStr



def write(writeFilePath, content):
    with open(writeFilePath, 'a') as file:
        for item in content:
            file.write("".join(item))
        file.write('\n')
    try:
        pass
    except BaseException as e:
        pass



def clear(writeFilePath):
    file = open(writeFilePath, 'w')
    file.closed



def duplicateRemoval(readDir,writeDir):
    lines_seen = set()
    outfile = open(writeDir, "w")
    f = open(readDir, "r")
    for line in f:
        if line not in lines_seen:
            outfile.write(line)
            lines_seen.add(line)
    outfile.close()

def is_lan(ip):
    try:
        return ipaddress.ip_address(ip.strip()).is_private
    except Exception as e:
        return False

    
def is_ipv6(address):
    try:
        ipaddress.IPv6Address(address)
        return True
    except ipaddress.AddressValueError:
        return False

def data_fragment(dataStr):    
    dataStr = bin(int(dataStr)).replace('0b','')
    for i in range(1,8-len(dataStr)+1):
        dataStr = '0' + dataStr
    return dataStr



def csvWrite(column,writePath):
    res = pd.DataFrame(columns=(column))
    res.to_csv(writePath,index=False,mode='a',encoding='utf8')



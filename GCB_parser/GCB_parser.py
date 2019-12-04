# -*- coding: utf-8 -*-
import sys,re, argparse
from lib.treelib import Tree,node  #https://treelib.readthedocs.io/en/latest/
from lib.device.firewall.fortinet import fortigate
def readPatterns(f):
    out = []
    lineCount = 0
    for line in f.readlines():
        lineCount += 1
        if re.search(fortigate.GCB_INDEX_PAT, line):
            out.append(line.strip().split(",",maxsplit=1))
        else:
            sys.exit("".join(["Invalid GCB index format at line#", str(lineCount) , " : ", line]))
    return out

def processing(device,patterns,config):
    if device.lower() == "fortigate":
        fortigate.process(patterns,config)
    else:
        fortigate.process(patterns,config)

parser = argparse.ArgumentParser()
parser.add_argument("-r", "--read", help="the path of configuration to be parsed")
parser.add_argument("-p", "--pattern", help="the path of GCB patterns")
parser.add_argument("-o", "--output", help="the path of output file")
parser.add_argument("-d", "--device", help="the device name, should be one of : FortiNet/Cisco/Juniper")
args = parser.parse_args()
CONFIG_FILE = args.read
GCB_PATTERN = args.pattern
OUTPUT_FILE = args.output
DEVICE      = args.device

tree = []
#open files 
try:
    config = open(CONFIG_FILE)
except:
    sys.exit("".join(["Unable to open configuration : ",CONFIG_FILE]))
try:
    gcb_pat = open(GCB_PATTERN)
except:
    sys.exit("".join(["Unable to open pattern file : ",GCB_PATTERN]))
try:
    output = open(OUTPUT_FILE,"w")
except:
    sys.exit("".join(["Unable to open output file : ",OUTPUT_FILE]))

patterns = readPatterns(gcb_pat) # read the GCB�@patterns
processing(DEVICE,patterns,config)

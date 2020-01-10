# -*- coding: utf-8 -*-
import sys,re, argparse
from lib.treelib import Tree,node  #https://treelib.readthedocs.io/en/latest/
from lib.device.firewall.fortinet import fortigate
def readPatterns(f):
    out = dict()
    lineCount = 0
    for line in f.readlines():
        lineCount += 1
        if re.search(fortigate.GCB_INDEX_PAT, line):
            tmpList = []
            [key,patterns] = line.strip().split(",",maxsplit=1)
            for p in patterns.split(","):
                (new_string, number_of_subs_made) =   re.subn("[<|\"].*[>|\"]",".*",p)
                tmpList.append({"pattern":new_string,"fuzzyMatch":(number_of_subs_made > 0)})
            out[key] = tmpList
        else:
            sys.exit("".join(["Invalid GCB index format at line#", str(lineCount) , " : ", line]))
    return out

def config2List(device,patterns,config):
    if device.lower() == "fortigate":
        return fortigate.process(patterns,config)
    else:
        return fortigate.process(patterns,config)

parser = argparse.ArgumentParser()
parser.add_argument("-r", "--read", help = "the path of configuration to be parsed")
parser.add_argument("-p", "--pattern", help = "the path of GCB patterns")
parser.add_argument("-o", "--output", help = "the path of output file")
parser.add_argument("-d", "--device", help = "the device name, should be one of : FortiNet/Cisco/Juniper")
parser.add_argument("--debug", help = "enter debug mode",action="store_true", default=False)
parser.add_argument("--nonGCB", help = "input configuration is not GCB",action="store_true", default=False)
args = parser.parse_args()
CONFIG_FILE = args.read
GCB_PATTERN = args.pattern
OUTPUT_FILE = args.output
DEVICE      = args.device
DEBUG_MODE  = args.debug
NONGCB      = args.nonGCB

#open files 
try:
    config_file = open(CONFIG_FILE)
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

if DEVICE.lower() == "fortigate":
    configList = fortigate.config2List(patterns,config_file,DEBUG_MODE)
else:
    configList = fortigate.config2List(patterns,config_file,DEBUG_MODE)

for [gcb, configPattern] in patterns.items():
    parsed = fortigate.recognizeGCB(gcb,configPattern,configList,DEBUG_MODE)
    result = fortigate.validateGCB(gcb, parsed,DEBUG_MODE)
    if result:
        for r in range(len(result)):
            out = ",".join([gcb,",".join(parsed[r]) if parsed else "",fortigate.VALIDATION_DESCRIP[result[r]]])
            print(out)
            output.write(out+"\n")
    else:
        out = ",".join([gcb, fortigate.VALIDATION_DESCRIP[fortigate.NOT_SETTING]])
        print(out)
        output.write(out+"\n")
    
output.close()

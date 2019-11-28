# -*- coding: utf-8 -*-
import sys,re
from lib.treelib import Tree  #https://treelib.readthedocs.io/en/latest/
CONFIG_FILE = "input/FortiGate100D_config.txt"
GCB_PATTERN = "input/GCB_FortiGate.txt"
LEADING_SPACE = " " * 4
def readValidcmd(patterns):
    out = set()
    for line in patterns:
        out.add(line[-1].split(",")[0])
    return out
def isnt_root(node):
    return not (node.identifier == "root")
def getLevel(line):
    return int((len(line)-len(line.lstrip()))/len(LEADING_SPACE))
def gcb_search(nodes):
    for n in nodes:
        if n.tag == "config system global":
            assert(n)
def readPatterns(f):
    out = []
    for line in f.readlines():
        out.append(line.split(",",maxsplit=1))
    return out
def recognizeGCB(gcbIndex,confPattern,root):
    out = None
    curNode = root
    if True:#gcbIndex == "GCB_Fortinet_Fortigate_01":
        for cmd in confPattern.strip().split(","):
            match = flagFuzzyMatch = False
            if re.search('.*<.*>.*',cmd):
                cmd = re.search('.*(?=<)',cmd).group(0)
                flagFuzzyMatch = True
            for child in tree.children(curNode.identifier):
                match = child.tag.startswith(cmd) if flagFuzzyMatch else (cmd == child.tag)
                if match:
                    curNode = child
                    break
        if match:                
            result = []
            for n in tree.rsearch(curNode.identifier,isnt_root):
                result.insert(0, tree.get_node(n).tag)
            out = ",".join(result)   
    return out
tree = []

#Read files 
try:
    config = open(CONFIG_FILE)
except:
    sys.exit("Unable to open configuration ",CONFIG_FILE)
try:
    gcb_pat = open(GCB_PATTERN)
except:
    sys.exit("Unable to open pattern file ",GCB_PATTERN)

patterns = readPatterns(gcb_pat) # read the GCB�@patterns
#parse the neccessary configuration commands
configCmd = readValidcmd(patterns)
flagEnterConfigSec = False # flag of config section entered
lineCount = 0
curLevel = preLevel = 0
tree = Tree()
curNode = tree.create_node(tag="root", identifier="root")

for line in config.readlines():
    lineCount = lineCount+1
    line = line.rstrip() #ignore tailing space or newline
    
    if (len(line) == 0): # skip empty line
        continue
    curLevel = getLevel(line)
    
    
    if (not flagEnterConfigSec and not line[0].isspace() and line in configCmd): # a new configuration section found
        flagEnterConfigSec = True
        [tag,value] = line.split(" ",maxsplit=1)
        curNode = tree.create_node(identifier='{:08d}'.format(lineCount),tag=line.strip(), parent="root")
    elif (flagEnterConfigSec and (line.strip() == "end" or line.strip() == "next")): # the end if configuration section
        flagEnterConfigSec = False
        curNode = tree.parent(curNode.identifier)
    elif flagEnterConfigSec:
        [tag,value] = line.lstrip().split(" ",maxsplit=1)
        if (curLevel > preLevel):
            curNode = tree.create_node(identifier='{:08d}'.format(lineCount),tag=line.strip(),parent=curNode)
        else:
            curNode = tree.create_node(identifier='{:08d}'.format(lineCount),tag=line.strip(),parent=curNode.bpointer)
    preLevel = curLevel

root = tree.parent(curNode.identifier)

for p in patterns:
    [gcb, config] = p
    out = recognizeGCB(gcb,config,root)
    if out:
        print(",".join([gcb,out]))
    else:
        print(gcb+",None")

        
        
        
        
        
    
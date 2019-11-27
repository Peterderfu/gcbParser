import xml.etree.ElementTree as ET
import xml.dom.minidom
import sys
from treelib import Node, Tree
# tree = ET.parse('config.xml')
# root = tree.getroot()
# lines = "config system interface,edit wan1,set allowaccess http".split(",")
# for l in lines:
#     [cmd,value] = l.strip().split(" ",maxsplit=1)
#     path = cmd
#     out = tree.iterfind(path)
#     for elem in out:
#         print((" ".join([elem.tag ,elem.text])))
def readValidcmd(f):
    out = set()
    for line in f.readlines():
        out.add(line.split(",")[0])
    return out
def prettyXML(ele):
    print(xml.dom.minidom.parseString(ET.tostring(ele)).toprettyxml())

CONFIG_FILE = "FortiGate100D_config.txt"
GCB_PATTERN = "GCB_FortiGate.txt"
LEADING_SPACE = " " * 4
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


#parse the neccessary configuration commands
configCmd = readValidcmd(gcb_pat)
flagEnterConfigSec = False # flag of config section entered
tree.append(ET.Element("data"))
lineCount = 0
curLevel = preLevel = 0
for line in config.readlines():
    lineCount = lineCount+1
    line = line.rstrip() #ignore tailing space or newline
    
    if (len(line) == 0): # skip empty line
        continue
    curLevel = int((len(line)-len(line.lstrip()))/len(LEADING_SPACE))
    
    if (not flagEnterConfigSec and not line[0].isspace() and line in configCmd): # a new configuration section found
        flagEnterConfigSec = True
        [tag,value] = line.split(" ",maxsplit=1)
#         tree.append(ET.SubElement(tree[0],tag,{'param':value}))
        tree.extend([ET.SubElement(tree[0],tag,{'param':value})])
#         node.text = value
#         ET.dump(tree[0])
        
#         prettyXML(tree[0])
    elif (flagEnterConfigSec and line == "".join([LEADING_SPACE*(curLevel-1),"end"])): # the end if configuration section
        flagEnterConfigSec = False
        curLevel = curLevel-1
    elif flagEnterConfigSec:
#         level = int((len(line)-len(line.lstrip()))/len(LEADING_SPACE))
        [tag,value] = line.lstrip().split(" ",maxsplit=1)
        if (curLevel > preLevel):
            ET.SubElement(tree[curLevel],tag)
        node = ET.SubElement(tree[curLevel],tag)
        node.text = value
        tree.append(node)
    preLevel = curLevel
        
        
        
        
        
    
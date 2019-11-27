# import xml.etree.ElementTree as ET
# import xml.dom.minidom
import sys
from treelib import Tree  #https://treelib.readthedocs.io/en/latest/
CONFIG_FILE = "FortiGate100D_config.txt"
GCB_PATTERN = "GCB_FortiGate.txt"
LEADING_SPACE = " " * 4
def readValidcmd(f):
    out = set()
    for line in f.readlines():
        out.add(line.split(",")[0])
    return out
# def prettyXML(ele):
#     print(xml.dom.minidom.parseString(ET.tostring(ele)).toprettyxml())

def getLevel(line):
    return int((len(line)-len(line.lstrip()))/len(LEADING_SPACE))
def gcb_search(nodes):
    for n in nodes:
        if n.tag == "config system global":
            assert(n)
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
nodes = tree.all_nodes()
gcb_search(nodes)
# tree.show()
        
        
        
        
        
    
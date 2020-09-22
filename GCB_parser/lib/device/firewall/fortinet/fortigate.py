# -*- coding: utf-8 -*-
from lib.treelib import Tree
import re, pprint,sys,os
GCB_INDEX_PAT = '^GCB_[a-zA-Z0-9]+_[a-zA-Z0-9]+_\d{2},\w+'
NONGCB_INDEX_PAT = '\d+,\w+'
LEADING_SPACE = " " * 4
VALID_SETTING = '0'
INVALID_SETTING = '1'
NOT_SETTING = '2'
TREE_ROOT = "root"
VALIDATION_DESCRIP = {VALID_SETTING: "正確設定", INVALID_SETTING: "錯誤設定",NOT_SETTING: "尚未設定"}
plugins = dict()
def register(func):
    """Register a function as a plugin by decorator"""
    plugins.update({func.__name__:func})
    return func
def compareMethod_1(pattern, config,start=-1):
# input: 
#     pattern = [prefix,option]
#     config: the string to be compared with pattern
# procedure:
#     compare the config with pattern.prefix and pattern.option
    if not config[start].startswith(pattern[0]):
        return NOT_SETTING
    else:
        if config[start].split(" ")[-1] == pattern[1]:
            return  VALID_SETTING
        else:
            return INVALID_SETTING
def compareMethod_2(op,pattern,config):
    start = -1
    if not config[start].startswith(pattern[0]):
        return NOT_SETTING
    else:
        operand = [int(config[start].split(" ")[-1]),int(pattern[1])]
        if   op == "<":
            tmp = operand[0] <  operand[1]
        elif op == ">":
            tmp = operand[0] >  operand[1]
        elif op == ">=":
            tmp = operand[0] >= operand[1]
        elif op == "<=":
            tmp = operand[0] <= operand[1]
        elif op == "!=":
            tmp = operand[0] != operand[1]
        else:
            sys.exit("Invalid comparison operator")
        return VALID_SETTING if (tmp == True) else INVALID_SETTING
@register
def validate_GCB_Fortinet_Fortigate_01(config):
#NO http/telnet following "set allowaccess"
#config pattern : set allowaccess <proto1> <proto2> ...
    NOT_ALLOWED_PROTO = {"http","telnet"}
    if config and len(config)==3:
        for s in [c.lower() for c in config[-1].split(" ")[2:]]:
            if (s in NOT_ALLOWED_PROTO):
                return INVALID_SETTING
            
        return VALID_SETTING
    else:
        return NOT_SETTING
@register
def validate_GCB_Fortinet_Fortigate_02(config):
#pattern :　set description <text>
    if config and len(config)==3:
        s = config[-1].split(" ",maxsplit=2)
        if (len(s) >2):
            return INVALID_SETTING if (s[-1].find("\'\'") != -1 or s[-1].find("\"\"") != -1) else VALID_SETTING
        else:
            return INVALID_SETTING
    else:
        return NOT_SETTING
@register
def validate_GCB_Fortinet_Fortigate_03(config):
#pattern :　set broadcast-forward disable
    return compareMethod_1(["set broadcast-forward", "disable"],config)
@register
def validate_GCB_Fortinet_Fortigate_04(config):
#pattern :　set drop-fragment enable
    return compareMethod_1(["set drop-fragment", "enable"], config)
@register
def validate_GCB_Fortinet_Fortigate_05(config):
#pattern :　set drop-overlappedfragment enable 
    return compareMethod_1(["set drop-overlappedfragment","enable"],config)
@register
def validate_GCB_Fortinet_Fortigate_06(config):
#pattern :　set fail-detect enable 
    return compareMethod_1(["set fail-detect", "enable"],config)
@register
def validate_GCB_Fortinet_Fortigate_07(config):
#pattern :　set status enable
    return compareMethod_1(["set status", "enable"],config) 
@register
def validate_GCB_Fortinet_Fortigate_08(config):
#pattern :　set apply-to admin-password 
    return compareMethod_1(["set apply-to", "admin-password"],config)
@register
def validate_GCB_Fortinet_Fortigate_09(config):
#pattern : "set min-lower-case-letter <number>" , and number >=1
    return compareMethod_2(">=",["set min-lower-case-letter", "1"],config)  
@register
def validate_GCB_Fortinet_Fortigate_10(config):
#pattern : "set min-upper-case-letter <number>" , and number >=1
    return compareMethod_2(">=",["set min-upper-case-letter", "1"],config)
@register
def validate_GCB_Fortinet_Fortigate_11(config):
#pattern : "set min-non-alphanumeric <number>" , and number >=1
    return compareMethod_2(">=",["set min-non-alphanumeric", "1"],config)
@register
def validate_GCB_Fortinet_Fortigate_12(config):
#pattern : "set min-number <number>" , and number >=1
    return compareMethod_2(">=",["set min-number", "1"],config)
@register
def validate_GCB_Fortinet_Fortigate_13(config):
#pattern : "set minimum-length <number>" , and number >=12
    return compareMethod_2(">=",["set minimum-length", "12"],config)
@register
def validate_GCB_Fortinet_Fortigate_14(config):
#pattern :　set change-4-characters enable 
    return compareMethod_1(["set change-4-characters", "enable"],config)
@register
def validate_GCB_Fortinet_Fortigate_15(config):
#pattern :　set expire-status enable 
    return compareMethod_1(["set expire-status", "enable"],config)
@register
def validate_GCB_Fortinet_Fortigate_16(config):
#pattern :　set expire-day 14
#     return compareMethod_2("<=",["set expire-day", "14"],config)
    return compareMethod_2("<=",["set expire-day", "90"],config)
@register
def validate_GCB_Fortinet_Fortigate_17(config):
#pattern :　set ntpsync enable 
    return compareMethod_1(["set ntpsync", "enable"],config)
@register
def validate_GCB_Fortinet_Fortigate_18(config):
#pattern :　set ntp-server1 <ipv4_addr>,set ntp-server2 <ipv4_addr>
    ipv4re = '([0-9]{1,3}\.){3}[0-9]{1,3}' #ipv4 regular expression
    if (config and len(config)==3):
        [s1,ip1] = config[1].strip().rsplit(" ", maxsplit=1)
        [s2,ip2] = config[2].strip().rsplit(" ", maxsplit=1)
        return VALID_SETTING if (s1 == "set ntp-server1" and re.search(ipv4re, ip1) and s2 == "set ntp-server2" and re.search(ipv4re, ip2)) else INVALID_SETTING
    else:
        return NOT_SETTING
@register
def validate_GCB_Fortinet_Fortigate_19(config):
#pattern :　set ntpv3 enable 
    return compareMethod_1(["set ntpv3", "enable"],config)
@register
def validate_GCB_Fortinet_Fortigate_20(config):
#pattern :　set password <admin_password>
    if config and len(config)==3:
        return VALID_SETTING if (len(config[-1].split(" ")) >= 2) else INVALID_SETTING
    else:
        return NOT_SETTING
@register
def validate_GCB_Fortinet_Fortigate_21(config):
#pattern :　set force-password-change enable 
    return compareMethod_1(["set force-password-change", "enable"],config)
@register
def validate_GCB_Fortinet_Fortigate_22(config):
#pattern :　set guest-auth disable
    return compareMethod_1(["set guest-auth", "disable"], config)
@register
def validate_GCB_Fortinet_Fortigate_23(config):
#pattern :　set allow-remove-adminsession disable 
    return compareMethod_1(["set allow-remove-adminsession", "disable"],config)
@register
def validate_GCB_Fortinet_Fortigate_24(config):
#pattern :　set auto-install-config disable 
    return compareMethod_1(["set auto-install-config", "disable"],config)
@register
def validate_GCB_Fortinet_Fortigate_25(config):
#pattern :　set auto-install-image disable 
    return compareMethod_1(["set auto-install-image", "disable"],config)
@register
def validate_GCB_Fortinet_Fortigate_26(config):
#pattern :　set admin-https-ssl-versions tlsv1-0 tlsv1-1 tlsv1-2
    SSL_SETS = ["tlsv1-0", "tlsv1-1", "tlsv1-2"]
    s = config[-1].split(" ",maxsplit=2)[-1].split(" ")
    if not config[-1].startswith("set admin-https-ssl-versions"):
        return NOT_SETTING
    elif sum([c in SSL_SETS for c in s])==len(s):
        return VALID_SETTING
    else:
        return INVALID_SETTING
@register
def validate_GCB_Fortinet_Fortigate_27(config):
#pattern :　set admin-https-redirect enable 
    return compareMethod_1(["set admin-https-redirect", "enable"],config)
#     return (VALID_SETTING if (config[-1].strip() == "set admin-https-redirect enable") else INVALID_SETTING) if (config and len(config)==2) else NOT_SETTING
@register
def validate_GCB_Fortinet_Fortigate_28(config):
#pattern :　set admin-lockout-threshold <number>, number<=3
    return compareMethod_2("<=",["set admin-lockout-threshold", "3"],config)  
@register
def validate_GCB_Fortinet_Fortigate_29(config):
#pattern :　set admin-lockout-duration <number>, number >=900
    return compareMethod_2(">=",["set admin-lockout-duration", "900"],config)  
#     return compareMethod_1(["set admin-lockout-duration", "900"],config) 
@register
def validate_GCB_Fortinet_Fortigate_30(config):
#pattern :　set hostname <unithostname>
#https://www.manageengine.com/network-monitoring/device-discovery/fortinet-performance-monitoring.html
#if hostname has the device number in url above, this config is invalid
    devices = ["fgt","fg","fr","fw"]
    if config and len(config)==2:
        if (len(config[-1].split(" ")) >= 2): 
            for d in devices:
                if str(config[-1].split(" ")[-1]).lower().strip("\"").startswith(d):
                    return INVALID_SETTING
            return VALID_SETTING
        else: 
            return INVALID_SETTING
    else:
        return NOT_SETTING
@register
def validate_GCB_Fortinet_Fortigate_31(config):
#pattern :　 set fds-statistics disable 
    return compareMethod_1(["set fds-statistics", "disable"],config)
@register
def validate_GCB_Fortinet_Fortigate_32(config):
#pattern : "set admin-ssh-grace-time <number>" , and number <=900
    return compareMethod_2("<=",["set admin-ssh-grace-time", "900"],config)  
@register
def validate_GCB_Fortinet_Fortigate_33(config):
#pattern : "set admin-login-max <number>" , and number <=1
    return compareMethod_2("<=",["set admin-login-max", "1"],config)  
@register
def validate_GCB_Fortinet_Fortigate_34(config):
#pattern :　 set admin-reset-button disable 
    return compareMethod_1(["set admin-reset-button", "disable"],config)
@register
def validate_GCB_Fortinet_Fortigate_35(config):
#pattern :　 set cfg-save manual 
    return compareMethod_1(["set cfg-save", "manual"],config)
@register
def validate_GCB_Fortinet_Fortigate_36(config):
#pattern :　 set security-level auth-priv 
    return compareMethod_1(["set security-level", "auth-priv"],config)
@register
def validate_GCB_Fortinet_Fortigate_37(config):
#pattern :　 set priv-proto aes256 
    return compareMethod_1(["set priv-proto", "aes256"],config)
@register
def validate_GCB_Fortinet_Fortigate_38(config):
#pattern :　 set auth-proto sha 
    return compareMethod_1(["set priv-proto", "sha"],config)
@register
def validate_GCB_Fortinet_Fortigate_39(config):
#pattern : set query-port <port_int> , and port_int !=161
    return compareMethod_2("!=",["set query-port", "161"],config)  
@register
def validate_GCB_Fortinet_Fortigate_40(config):
#pattern :　set name <community_name>
    if config and len(config)==3:
        set_community_cmd = config[-1].split(" ")
        if (len(set_community_cmd) >= 2):
            community = set_community_cmd[-1].lower()
            if (community.startswith("public") or community.startswith("private")):
                return INVALID_SETTING
            else:
                return VALID_SETTING
#         
#         return VALID_SETTING if (len(set_community_cmd) >= 2 and ) else INVALID_SETTING
#     else:
#         return NOT_SETTING
    return NOT_SETTING
@register
def validate_GCB_Fortinet_Fortigate_41(config):
#pattern :　 set query-v1-status disable 
    return compareMethod_1(["set query-v1-status", "disable"],config)
@register
def validate_GCB_Fortinet_Fortigate_42(config):
#pattern : set query-v1-prot <port_int> , and port_int !=161
    return compareMethod_2("!=",["set query-v1-prot", "161"],config)  
@register
def validate_GCB_Fortinet_Fortigate_43(config):
#pattern :　 set query-v2c-status disable 
    return compareMethod_1(["set query-v2c-status", "disable"],config)
@register
def validate_GCB_Fortinet_Fortigate_44(config):
#pattern : set query-v2c-prot <port_int> , and port_int !=161
    return compareMethod_2("!=",["set query-v2c-prot", "161"],config)  
@register
def validate_GCB_Fortinet_Fortigate_45(config):
#pattern :　 set log-invalid-packet enable
    return compareMethod_1(["set log-invalid-packet", "enable"],config) 
@register
def validate_GCB_Fortinet_Fortigate_46(config):
#pattern :　 set user-anonymize disable 
    return compareMethod_1(["set user-anonymize", "disable"],config)

def readValidcmd(patterns):
    out = set()
    for line in patterns.values():
        out.add(line[0]['pattern'])
    return out
def isnt_root(node):
    return not (node.identifier == TREE_ROOT)
def getLevel(line):
    return int((len(line)-len(line.lstrip()))/len(LEADING_SPACE))
def cmp(config, setting):
    return (re.search(config['pattern'],setting) is not None) if config['fuzzyMatch'] else (config['pattern'] == setting)
     
def recognizeGCB(gcbIndex,confPattern,paths,debug_mode=False):
    out = []
    tmpOut = set()
    for path in paths: # examine every path 
        if len(path) < len(confPattern): # path with length smaller than confPattern is invalid 
            continue
        matched = False
        c_start = p_start = 0
        for c in confPattern[c_start:]:
            for p in path[p_start:]:
                matched = cmp(c,p.split(":")[-1] if debug_mode else p)
                if matched:
                    p_start += 1
                    break
            if not matched:
                break
        if matched:
            s = "".join(path[:path.index(p)+1])
            if not s in tmpOut:
                out.append(path[:path.index(p)+1])
                tmpOut.add(s)
    return out
def validateGCB(gcbIndex,config,debug_mode = False,nonGCB = False):
    indexPat = "^GCB_Fortinet_Fortigate_[0-9]{2}" if not nonGCB else "^\d+"
        
    if not re.search(indexPat, gcbIndex):
        return None
    else:
        if debug_mode:
            config = [[d.split(":")[-1] for d in c] for c in config] # remove line number
        index = "validate_" + gcbIndex
#         for c in config:
#             print(c)
#         out = [plugins[index](c) for c in config]
#         return out 
        return [plugins[index](c) for c in config]
def isConfigBlkEnd(line):
    return (line.lower() in ["end","next"])
def debug(lineCount,preLevel,curLevel,curNode,curTop):
    tree.show(key=lambda x:x.identifier)
def shiftUpParent(tree,node, level):
    while (level > 0):
        node = tree.parent(node.identifier)
        level -= 1
    return node   
def config2List(patterns,config,debug_mode=False):
    configCmd = readValidcmd(patterns)
    flagEnterConfigBlk = False # flag of config block entered
    flagSkipConfigBlk  = False # flag of skipping config block
    lineCount = 0              # the number of lines processed
    curLevel = -1    # the hierarchical position this line
    preLevel = -1    # the hierarchical position of previous line in processing
    
    #start to feed configuration item into data structure of tree
    tree = Tree()
    curNode = tree.create_node(tag=TREE_ROOT, identifier=TREE_ROOT) # create a tree with root
    curTop = preNode = curNode  # set parent to current node(root now)
    
    for line in config.readlines():
        lineCount += 1
        line = line.rstrip() #ignore tailing space or newline
        if (len(line) == 0): # skip empty line
            continue # skip to next line
        if (re.search("^#\w+", line)): # skip commented line
            continue # skip to next line
        if (re.search("^#\w+", line)): # skip commented line
            continue # skip to next line
        if (line.startswith("--More--")): # skip "--More--" seperator 
            continue # skip to next line
        
        preLevel = curLevel
        preNode = curNode
        curLevel = getLevel(line) # get the hierarchical position of this line 
        
        if (flagSkipConfigBlk == True):  # if SkipConfigBlk flag set to true previously, we should skip to next line based on isConfigBlkEnd 
            flagSkipConfigBlk = not isConfigBlkEnd(line)  # the condition of config block end occurs 
            continue # skip to next line
        
        # flagSkipConfigBlk is False and process goes below
        
        if (flagEnterConfigBlk == False): # 
            if (re.search("^config\s\w+", line) and (line in configCmd)): # search config block start
                flagEnterConfigBlk = True
            else:
                flagSkipConfigBlk = True # this config blocktion is not needed for further processing
                continue # skip to next line
        else:
            if (isConfigBlkEnd(line)): # is top most config block end?
                flagEnterConfigBlk = False
                curTop = tree.get_node(tree.root)
                continue
            else:
                if (curLevel < preLevel):
                    curTop = shiftUpParent(tree,curTop,preLevel-curLevel)
                    if (isConfigBlkEnd(line.lstrip())):  # is line matched block end?
                        continue
        if (curLevel > preLevel):
            curTop = preNode
        curNode = tree.create_node(identifier='{:08d}'.format(lineCount),tag=line.lstrip(), parent=curTop)
    
    res = []
    paths = tree.paths_to_leaves()
    for path in paths:
        if debug_mode:
            res.append([":".join([tree.get_node(nid).identifier,tree.get_node(nid).tag]) for nid in path[1:]])
        else:
            res.append([tree.get_node(nid).tag for nid in path[1:]])
    return res # all paths from root to leaves

# -*- coding: utf-8 -*-
from lib.treelib import Tree
from contextlib import redirect_stdout
import re, pprint,sys
GCB_INDEX_PAT = '^GCB_[a-zA-Z0-9]+_[a-zA-Z0-9]+_\d{2},\w+'
LEADING_SPACE = " " * 4
VALID_SETTING = '0'
INVALID_SETTING = '1'
NOT_SETTING = '2'
TREE_ROOT = "root"
VALIDATION_DESCRIP = {VALID_SETTING: "正確設定", INVALID_SETTING: "錯誤設定",NOT_SETTING: "尚未設定"}
# class MatchRecord(object):
#     def __init__(self, isMatch):
#         self.childMatch = isMatch[0]
#         self.selfMatch  = isMatch[1]

def compareMethod_1(pattern, config):
# input: 
#     pattern = [prefix,option]
#     config: the string to be compared with pattern
# procedure:
#     compare the config with pattern.prefix and pattern.option
    if not config[-1].startswith(pattern[0]):
        return NOT_SETTING
    else:
        if config[-1].split(" ")[-1] == pattern[1]:
            return  VALID_SETTING
        else:
            return INVALID_SETTING
# def compareMethod_2("<",["set admin-lockout-threshold", "3"],config)
def compareMethod_2(op,pattern,config):
    if not config[-1].startswith(pattern[0]):
        return NOT_SETTING
    else:
        if op == "<":
            out = int(config[-1].split(" ")[-1]) < int(pattern[1])
        elif op == ">":
            out = int(config[-1].split(" ")[-1]) > int(pattern[1])
        elif op == ">=":
            out = int(config[-1].split(" ")[-1]) >= int(pattern[1])
        elif op == "<=":
            out = int(config[-1].split(" ")[-1]) <= int(pattern[1])
        elif op == "!=":
            out = int(config[-1].split(" ")[-1]) != int(pattern[1])
        else:
            sys.exit("Invalid comparison operator")
        return VALID_SETTING if (out == True) else INVALID_SETTING
def validate_GCB_Fortinet_Fortigate_01(config):
#NO http/telnet following "set allowaccess"
#config pattern : set allowaccess <proto1> <proto2> ...
    NOT_ALLOWED_PROTO = {"http","telnet"}
    if config and len(config)==3:
#         s = [c.lower() for c in config[-1].split(" ")[2:]]
        for s in [c.lower() for c in config[-1].split(" ")[2:]]:
            if (s in NOT_ALLOWED_PROTO):
                return INVALID_SETTING
            
        return VALID_SETTING
    else:
        return NOT_SETTING
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
def validate_GCB_Fortinet_Fortigate_03(config):
#pattern :　set broadcast-forward disable
    return compareMethod_1(["set broadcast-forward", "disable"],config)
def validate_GCB_Fortinet_Fortigate_04(config):
#pattern :　set drop-fragment enable
    return compareMethod_1(["set drop-fragment", "enable"], config)
def validate_GCB_Fortinet_Fortigate_05(config):
#pattern :　set drop-overlappedfragment enable 
    return compareMethod_1(["set drop-overlappedfragment","enable"],config)
def validate_GCB_Fortinet_Fortigate_06(config):
#pattern :　set fail-detect enable 
    return compareMethod_1(["set fail-detect", "enable"],config)
def validate_GCB_Fortinet_Fortigate_07(config):
#pattern :　set status enable
    return compareMethod_1(["set status", "enable"],config) 
def validate_GCB_Fortinet_Fortigate_08(config):
#pattern :　set apply-to admin-password 
    return compareMethod_1(["set apply-to", "admin-password"],config)
def validate_GCB_Fortinet_Fortigate_09(config):
#pattern : "set min-lower-case-letter <number>" , and number >=1
    return compareMethod_2("=>",["set min-lower-case-letter", "1"],config)  
#     if (config and len(config)==2):
#         [s,n] = config[-1].strip().rsplit(" ", maxsplit=1)
#         return VALID_SETTING if (s == "set min-lower-case-letter" and int(n) >= 1) else INVALID_SETTING
#     else:
#         return NOT_SETTING
def validate_GCB_Fortinet_Fortigate_10(config):
#pattern : "set min-upper-case-letter <number>" , and number >=1
    return compareMethod_2("=>",["set min-upper-case-letter", "1"],config)
#     if (config and len(config)==2):
#         [s,n] = config[-1].strip().rsplit(" ", maxsplit=1)
#         return VALID_SETTING if (s == "set min-upper-case-letter" and int(n) >= 1) else INVALID_SETTING
#     else:
#         return NOT_SETTING
def validate_GCB_Fortinet_Fortigate_11(config):
#pattern : "set min-non-alphanumeric <number>" , and number >=1
    return compareMethod_2("=>",["set min-non-alphanumeric", "1"],config)
#     if (config and len(config)==2):
#         [s,n] = config[-1].strip().rsplit(" ", maxsplit=1)
#         return VALID_SETTING if (s == "set min-non-alphanumeric" and int(n) >= 1) else INVALID_SETTING
#     else:
#         return NOT_SETTING
def validate_GCB_Fortinet_Fortigate_12(config):
#pattern : "set min-number <number>" , and number >=1
    return compareMethod_2("=>",["set min-number", "1"],config)
#     if (config and len(config)==2):
#         [s,n] = config[-1].strip().rsplit(" ", maxsplit=1)
#         return VALID_SETTING if (s == "set min-number" and int(n) >= 1) else INVALID_SETTING
#     else:
#         return NOT_SETTING
def validate_GCB_Fortinet_Fortigate_13(config):
#pattern : "set minimum-length <number>" , and number >=1
    return compareMethod_2("=>",["set minimum-length", "1"],config)
#     if (config and len(config)==2):
#         [s,n] = config[-1].strip().rsplit(" ", maxsplit=1)
#         return VALID_SETTING if (s == "set minimum-length" and int(n) >= 1) else INVALID_SETTING
#     else:
#         return NOT_SETTING
def validate_GCB_Fortinet_Fortigate_14(config):
#pattern :　set change-4-characters enable 
    return compareMethod_1(["set change-4-characters", "enable"],config)
def validate_GCB_Fortinet_Fortigate_15(config):
#pattern :　set expire-status enable 
    return compareMethod_1(["set expire-status", "enable"],config)
def validate_GCB_Fortinet_Fortigate_16(config):
#pattern :　set expire 90 
    return compareMethod_1(["set expire", "90"],config)
def validate_GCB_Fortinet_Fortigate_17(config):
#pattern :　set expire-day 14
    return compareMethod_1(["set expire-day", "14"],config)
def validate_GCB_Fortinet_Fortigate_18(config):
#pattern :　set ntpsync enable 
    return compareMethod_1(["set ntpsync", "enable"],config)
def validate_GCB_Fortinet_Fortigate_19(config):
#pattern :　set ntp-server1 <ipv4_addr>,set ntp-server2 <ipv4_addr>
    ipv4re = '([0-9]{1,3}\.){3}[0-9]{1,3}' #ipv4 regular expression
    if (config and len(config)==3):
        [s1,ip1] = config[1].strip().rsplit(" ", maxsplit=1)
        [s2,ip2] = config[2].strip().rsplit(" ", maxsplit=1)
        return VALID_SETTING if (s1 == "set ntp-server1" and re.search(ipv4re, ip1) and s2 == "set ntp-server2" and re.search(ipv4re, ip2)) else INVALID_SETTING
    else:
        return NOT_SETTING
def validate_GCB_Fortinet_Fortigate_20(config):
#pattern :　set ntpv3 enable 
    return compareMethod_1(["set ntpv3", "enable"],config)
def validate_GCB_Fortinet_Fortigate_21(config):
#pattern :　set password <admin_password>
    if config and len(config)==3:
        return VALID_SETTING if (len(config[-1].split(" ")) >= 2) else INVALID_SETTING
    else:
        return NOT_SETTING
def validate_GCB_Fortinet_Fortigate_22(config):
#pattern :　set force-password-change enable 
    return compareMethod_1(["set force-password-change", "enable"],config)
def validate_GCB_Fortinet_Fortigate_23(config):
#pattern :　set guest-auth disable
    return compareMethod_1(["set guest-auth", "disable"], config)
def validate_GCB_Fortinet_Fortigate_24(config):
#pattern :　set allow-remove-adminsession disable 
    return compareMethod_1(["set allow-remove-adminsession", "disable"],config)
def validate_GCB_Fortinet_Fortigate_25(config):
#pattern :　set auto-install-config disable 
    return compareMethod_1(["set auto-install-config", "disable"],config)
def validate_GCB_Fortinet_Fortigate_26(config):
#pattern :　set auto-install-image disable 
    return compareMethod_1(["set auto-install-image", "disable"],config)
def validate_GCB_Fortinet_Fortigate_27(config):
#pattern :　set admin-https-ssl-versions tlsv1-0 tlsv1-1 tlsv1-2 
    return compareMethod_1(["set admin-https-ssl-versions", "tlsv1-0 tlsv1-1 tlsv1-2"],config)
def validate_GCB_Fortinet_Fortigate_28(config):
#pattern :　set admin-https-redirect enable 
    return compareMethod_1(["set admin-https-redirect", "enable"],config)
#     return (VALID_SETTING if (config[-1].strip() == "set admin-https-redirect enable") else INVALID_SETTING) if (config and len(config)==2) else NOT_SETTING
def validate_GCB_Fortinet_Fortigate_29(config):
#pattern :　set admin-lockout-threshold 3
    return compareMethod_2("<=",["set admin-lockout-threshold", "3"],config)  
def validate_GCB_Fortinet_Fortigate_30(config):
#pattern :　set admin-lockout-duration 900
    return compareMethod_2(">=",["set admin-lockout-duration", "900"],config)  
#     return compareMethod_1(["set admin-lockout-duration", "900"],config) 
def validate_GCB_Fortinet_Fortigate_31(config):
#pattern :　set hostname <unithostname>
    if config and len(config)==2:
        return VALID_SETTING if (len(config[-1].split(" ")) >= 2) else INVALID_SETTING
    else:
        return NOT_SETTING
def validate_GCB_Fortinet_Fortigate_32(config):
#pattern :　 set fds-statistics disable 
    return compareMethod_1(["set fds-statistics", "disable"],config)
def validate_GCB_Fortinet_Fortigate_33(config):
#pattern : "set admin-ssh-grace-time <number>" , and number <=900
    return compareMethod_2("<=",["set admin-ssh-grace-time", "900"],config)  
#     if (config and len(config)==2):
#         [s,n] = config[-1].strip().rsplit(" ", maxsplit=1)
#         return VALID_SETTING if (s == "set admin-ssh-grace-time" and int(n) <= 900) else INVALID_SETTING
#     else:
#         return NOT_SETTING
def validate_GCB_Fortinet_Fortigate_34(config):
#pattern : "set admin-login-max <number>" , and number <=1
    return compareMethod_2("<=",["set admin-login-max", "1"],config)  
#     if (config and len(config)==2):
#         [s,n] = config[-1].strip().rsplit(" ", maxsplit=1)
#         return VALID_SETTING if (s == "set admin-login-max" and int(n) <= 1) else INVALID_SETTING
#     else:
#         return NOT_SETTING
def validate_GCB_Fortinet_Fortigate_35(config):
#pattern :　 set admin-reset-button disable 
    return compareMethod_1(["set admin-reset-button", "disable"],config)
def validate_GCB_Fortinet_Fortigate_36(config):
#pattern :　 set cfg-save manual 
    return compareMethod_1(["set cfg-save", "manual"],config)
def validate_GCB_Fortinet_Fortigate_37(config):
#pattern :　 set security-level auth-priv 
    return compareMethod_1(["set security-level", "auth-priv"],config)
def validate_GCB_Fortinet_Fortigate_38(config):
#pattern :　 set priv-proto aes256 
    return compareMethod_1(["set priv-proto", "aes256"],config)
def validate_GCB_Fortinet_Fortigate_39(config):
#pattern :　 set auth-proto sha 
    return compareMethod_1(["set priv-proto", "aes256"],config)
def validate_GCB_Fortinet_Fortigate_40(config):
#pattern : set query-port <port_int> , and port_int !=161
    if (config and len(config)==3):
        [s,n] = config[-1].strip().rsplit(" ", maxsplit=1)
        return VALID_SETTING if (s == "set query-port" and int(n) != 161) else INVALID_SETTING
    else:
        return NOT_SETTING
def validate_GCB_Fortinet_Fortigate_41(config):
#pattern :　set name <community_name>
    if config and len(config)==3:
        return VALID_SETTING if (len(config[-1].split(" ")) >= 2) else INVALID_SETTING
    else:
        return NOT_SETTING
def validate_GCB_Fortinet_Fortigate_42(config):
#pattern :　 set query-v1-status disable 
    return compareMethod_1(["set query-v1-status", "disable"],config)
def validate_GCB_Fortinet_Fortigate_43(config):
#pattern : set query-v1-prot <port_int> , and port_int !=161
    return compareMethod_2("!=",["set query-v1-prot", "161"],config)  
#     if (config and len(config)==3):
#         [s,n] = config[-1].strip().rsplit(" ", maxsplit=1)
#         return VALID_SETTING if (s == "set query-v1-prot" and int(n) != 161) else INVALID_SETTING
#     else:
#         return NOT_SETTING
def validate_GCB_Fortinet_Fortigate_44(config):
#pattern :　 set query-v2c-status disable 
    return compareMethod_1(["set query-v2c-status", "disable"],config)
def validate_GCB_Fortinet_Fortigate_45(config):
#pattern : set query-v2c-prot <port_int> , and port_int !=161
    return compareMethod_2("!=",["set query-v2c-prot", "161"],config)  
#     if (config and len(config)==3):
#         [s,n] = config[-1].strip().rsplit(" ", maxsplit=1)
#         return VALID_SETTING if (s == "set query-v2c-prot" and int(n) != 161) else INVALID_SETTING
#     else:
#         return NOT_SETTING
def validate_GCB_Fortinet_Fortigate_46(config):
#pattern :　 set log-invalid-packet enable
    return compareMethod_1(["set log-invalid-packet", "enable"],config) 
def validate_GCB_Fortinet_Fortigate_47(config):
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
def recognizeGCB(gcbIndex,confPattern,tree):
    out = []
    paths = tree.paths_to_leaves() # all paths from root to leaves
    
    for path in paths: # examine every path 
        matched = False
        for pattern in confPattern:
            # compare the individual pattern with nodes in path
            if ((pattern == confPattern[0]) or matched):
                curNode = 0
                while (curNode < len(path)):
                    #if current node in path matched to current pattern, step to the next node and pattern
                    if pattern['fuzzyMatch'] == True:
                        if re.search(pattern['pattern'],tree.get_node(path[curNode]).tag):
                            matched = True
                            break
                        else:
                            matched = False
                    else:
                        if (pattern['pattern'] == tree.get_node(path[curNode]).tag):
                            matched = True
                            break
                        else:
                            matched = False
                    curNode += 1
                        
        if matched:
            result = [tree.get_node(n).tag for n in path[1:]] # ignore root
            out.append(result)
    return out

def validateGCB(gcbIndex,config):
    if    gcbIndex == "GCB_Fortinet_Fortigate_01":
        return [validate_GCB_Fortinet_Fortigate_01(c) for c in config]
    elif  gcbIndex == "GCB_Fortinet_Fortigate_02":
        return [validate_GCB_Fortinet_Fortigate_02(c) for c in config]
    elif  gcbIndex == "GCB_Fortinet_Fortigate_03":
        return [validate_GCB_Fortinet_Fortigate_03(c) for c in config]
    elif  gcbIndex == "GCB_Fortinet_Fortigate_04":
        return [validate_GCB_Fortinet_Fortigate_04(c) for c in config]
    elif  gcbIndex == "GCB_Fortinet_Fortigate_05":
        return [validate_GCB_Fortinet_Fortigate_05(c) for c in config]
    elif  gcbIndex == "GCB_Fortinet_Fortigate_06":
        return [validate_GCB_Fortinet_Fortigate_06(c) for c in config]
    elif  gcbIndex == "GCB_Fortinet_Fortigate_07":
        return [validate_GCB_Fortinet_Fortigate_07(c) for c in config]
    elif  gcbIndex == "GCB_Fortinet_Fortigate_08":
        return [validate_GCB_Fortinet_Fortigate_08(c) for c in config]
    elif  gcbIndex == "GCB_Fortinet_Fortigate_09":
        return [validate_GCB_Fortinet_Fortigate_09(c) for c in config]
    elif  gcbIndex == "GCB_Fortinet_Fortigate_10":
        return [validate_GCB_Fortinet_Fortigate_10(c) for c in config]
    elif  gcbIndex == "GCB_Fortinet_Fortigate_11":
        return [validate_GCB_Fortinet_Fortigate_11(c) for c in config]
    elif  gcbIndex == "GCB_Fortinet_Fortigate_12":
        return [validate_GCB_Fortinet_Fortigate_12(c) for c in config]
    elif  gcbIndex == "GCB_Fortinet_Fortigate_13":
        return [validate_GCB_Fortinet_Fortigate_13(c) for c in config]
    elif  gcbIndex == "GCB_Fortinet_Fortigate_14":
        return [validate_GCB_Fortinet_Fortigate_14(c) for c in config]
    elif  gcbIndex == "GCB_Fortinet_Fortigate_15":
        return [validate_GCB_Fortinet_Fortigate_15(c) for c in config]
    elif  gcbIndex == "GCB_Fortinet_Fortigate_16":
        return [validate_GCB_Fortinet_Fortigate_16(c) for c in config]
    elif  gcbIndex == "GCB_Fortinet_Fortigate_17":
        return [validate_GCB_Fortinet_Fortigate_17(c) for c in config]
    elif  gcbIndex == "GCB_Fortinet_Fortigate_18":
        return [validate_GCB_Fortinet_Fortigate_18(c) for c in config]
    elif  gcbIndex == "GCB_Fortinet_Fortigate_19":
        return [validate_GCB_Fortinet_Fortigate_19(c) for c in config]
    elif  gcbIndex == "GCB_Fortinet_Fortigate_20":
        return [validate_GCB_Fortinet_Fortigate_20(c) for c in config]
    elif  gcbIndex == "GCB_Fortinet_Fortigate_21":
        return [validate_GCB_Fortinet_Fortigate_21(c) for c in config]
    elif  gcbIndex == "GCB_Fortinet_Fortigate_22":
        return [validate_GCB_Fortinet_Fortigate_22(c) for c in config]
    elif  gcbIndex == "GCB_Fortinet_Fortigate_23":
        return [validate_GCB_Fortinet_Fortigate_23(c) for c in config]
    elif  gcbIndex == "GCB_Fortinet_Fortigate_24":
        return [validate_GCB_Fortinet_Fortigate_24(c) for c in config]
    elif  gcbIndex == "GCB_Fortinet_Fortigate_25":
        return [validate_GCB_Fortinet_Fortigate_25(c) for c in config]
    elif  gcbIndex == "GCB_Fortinet_Fortigate_26":
        return [validate_GCB_Fortinet_Fortigate_26(c) for c in config]
    elif  gcbIndex == "GCB_Fortinet_Fortigate_27":
        return [validate_GCB_Fortinet_Fortigate_27(c) for c in config]
    elif  gcbIndex == "GCB_Fortinet_Fortigate_28":
        return [validate_GCB_Fortinet_Fortigate_28(c) for c in config]
    elif  gcbIndex == "GCB_Fortinet_Fortigate_29":
        return [validate_GCB_Fortinet_Fortigate_29(c) for c in config]
    elif  gcbIndex == "GCB_Fortinet_Fortigate_30":
        return [validate_GCB_Fortinet_Fortigate_30(c) for c in config]
    elif  gcbIndex == "GCB_Fortinet_Fortigate_31":
        return [validate_GCB_Fortinet_Fortigate_31(c) for c in config]
    elif  gcbIndex == "GCB_Fortinet_Fortigate_32":
        return [validate_GCB_Fortinet_Fortigate_32(c) for c in config]
    elif  gcbIndex == "GCB_Fortinet_Fortigate_33":
        return [validate_GCB_Fortinet_Fortigate_33(c) for c in config]
    elif  gcbIndex == "GCB_Fortinet_Fortigate_34":
        return [validate_GCB_Fortinet_Fortigate_34(c) for c in config]
    elif  gcbIndex == "GCB_Fortinet_Fortigate_35":
        return [validate_GCB_Fortinet_Fortigate_35(c) for c in config]
    elif  gcbIndex == "GCB_Fortinet_Fortigate_36":
        return [validate_GCB_Fortinet_Fortigate_36(c) for c in config]
    elif  gcbIndex == "GCB_Fortinet_Fortigate_37":
        return [validate_GCB_Fortinet_Fortigate_37(c) for c in config]
    elif  gcbIndex == "GCB_Fortinet_Fortigate_38":
        return [validate_GCB_Fortinet_Fortigate_38(c) for c in config]
    elif  gcbIndex == "GCB_Fortinet_Fortigate_39":
        return [validate_GCB_Fortinet_Fortigate_39(c) for c in config]
    elif  gcbIndex == "GCB_Fortinet_Fortigate_40":
        return [validate_GCB_Fortinet_Fortigate_40(c) for c in config]
    elif  gcbIndex == "GCB_Fortinet_Fortigate_41":
        return [validate_GCB_Fortinet_Fortigate_41(c) for c in config]
    elif  gcbIndex == "GCB_Fortinet_Fortigate_42":
        return [validate_GCB_Fortinet_Fortigate_42(c) for c in config]
    elif  gcbIndex == "GCB_Fortinet_Fortigate_43":
        return [validate_GCB_Fortinet_Fortigate_43(c) for c in config]
    elif  gcbIndex == "GCB_Fortinet_Fortigate_44":
        return [validate_GCB_Fortinet_Fortigate_44(c) for c in config]
    elif  gcbIndex == "GCB_Fortinet_Fortigate_45":
        return [validate_GCB_Fortinet_Fortigate_45(c) for c in config]
    elif  gcbIndex == "GCB_Fortinet_Fortigate_46":
        return [validate_GCB_Fortinet_Fortigate_46(c) for c in config]
    elif  gcbIndex == "GCB_Fortinet_Fortigate_47":
        return [validate_GCB_Fortinet_Fortigate_47(c) for c in config]
    else:
        return None
def isConfigSecEnd(line):
    return (line.lower() in ["end","next"])
def debug(lineCount,preLevel,curLevel,curNode,curTop):
    print(''.join(['line  :',str(lineCount)]))
    print(''.join(['preLv :',str(preLevel)]))
    print(''.join(['curLv :',str(curLevel)]))
    print(''.join(['curNd :',str(curNode.identifier)]))
    print(''.join(['curNd.p :',str(curNode.bpointer)]))
    print(''.join(['curTop :',str(curTop.identifier)]))
    print('-'*100)
def process(patterns,config):
    configCmd = readValidcmd(patterns)
    flagEnterConfigSec = False # flag of config section entered
    flagSkipConfigSec  = False # flag of skipping config section
    lineCount = 0              # the number of lines processed
    curLevel =  0    # the hierarchical position this line
    preLevel = -1    # the hierarchical position of previous line in processing
    
    #start to feed configuration item into data structure
    tree = Tree()
    curNode = tree.create_node(tag=TREE_ROOT, identifier=TREE_ROOT)
    curTop = curNode
    
    for line in config.readlines():
        lineCount += 1
        line = line.rstrip() #ignore tailing space or newline
        
        if (len(line) == 0): # skip empty line
            continue # skip to next line
        curLevel = getLevel(line) # get the hierarchical position of this line 
        line = line.strip()
        
        if (flagSkipConfigSec == True):  # if SkipConfigSec flag set to true previously, we should skip to next line based on isConfigSecEnd 
            flagSkipConfigSec = not isConfigSecEnd(line)  # the condition of config section end occurs 
            continue # skip to next line
        
        # flagSkipConfigSec is False and process goes below
        
        if (flagEnterConfigSec == False): # 
            if (re.search("^config\s\w+", line)): # search config section start
                if (line in configCmd): # test whether this config command searched needed or not?  
                    flagEnterConfigSec = True
                else:
                    flagSkipConfigSec = True # this config section is not needed for further processing
                    continue # skip to next line
            else:
                continue  # skip to next line
        # Below is config section processing
        if (isConfigSecEnd(line)):
            curNode = tree.parent(curNode.identifier)
            curTop = tree.parent(curNode.identifier)
            if (curLevel == 0):
                preLevel = -1
                curTop = tree.get_node(tree.root)
                curNode = curTop
            else:
                preLevel = curLevel
                
            flagEnterConfigSec = (curLevel != 0) #if curLevel == 0, flagEnterConfigSec = False
#             debug(lineCount,preLevel,curLevel, curNode, curTop)
        elif (curLevel > preLevel):
            curTop = curNode
            curNode = tree.create_node(identifier='{:08d}'.format(lineCount),tag=line, parent=curTop)
            preLevel = curLevel
#             debug(lineCount,preLevel,curLevel, curNode, curTop)
        elif (curLevel == preLevel):
            curNode = tree.create_node(identifier='{:08d}'.format(lineCount),tag=line, parent=curTop)
            preLevel = curLevel
#             debug(lineCount,preLevel,curLevel, curNode, curTop)
        else:
            pass   # should not stop here
    f = open('output/output.csv','w')
    for [gcb, config] in patterns.items():
        parsed = recognizeGCB(gcb,config,tree)
        result = validateGCB(gcb, parsed)
        if result:
            for r in range(len(result)):
                out = ",".join([gcb,",".join(parsed[r]) if parsed else "",VALIDATION_DESCRIP[result[r]]])
                print(out)
                f.write(out+"\n")
        else:
            out = ",".join([gcb, VALIDATION_DESCRIP[NOT_SETTING]])
            print(out)
            f.write(out+"\n")
        
    f.close()

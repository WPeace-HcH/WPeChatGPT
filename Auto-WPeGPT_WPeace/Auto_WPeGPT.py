import os
import idc
import idaapi
import idautils
import re
from collections import defaultdict
from anytree import Node, RenderTree


def makeDir():
    cwd = os.getcwd()
    idb_path = idc.get_idb_path()
    idb_name = os.path.basename(idb_path)
    idb_name = 'WPe_' + idb_name
    folder_path = os.path.join(cwd, idb_name) + '\\'
    if not os.path.exists(folder_path):
        os.makedirs(folder_path)
        print("Auto-WPeGPT have created the dir:", '"' + folder_path + '"', ":)@WPeace")
    else:
        print("Auto-WPeGPT have found the dir:", '"' + folder_path + '"', ":)@WPeace")
    return folder_path

def getStrings(fileDir):
    strList = []
    for s in idautils.Strings():
        if str(s) in strList:
            continue
        sysFlag = 0
        xrefCount = len(list(idautils.XrefsTo(s.ea)))
        if xrefCount != 0:
            for xref in idautils.XrefsTo(s.ea):
                strAddr = xref.frm
                funcName = idc.get_func_name(strAddr)
                if len(re.findall("^_.*", funcName)) != 0:
                    sysFlag = 1
                    break
                else:
                    func_ea = idc.get_name_ea_simple(funcName)
                    for xcaller in idautils.XrefsTo(func_ea):
                        callerFuncName = idc.get_func_name(xcaller.frm)
                        if len(re.findall("^_.*", callerFuncName)) != 0:
                            sysFlag = 1
            if sysFlag == 0:
                string = str(s).replace('\n', '').replace('\r', '').replace('\a', '').replace('\t', '').replace(' ', '')
                strList.append(string)
    filename = fileDir + "effectiveStrings.txt"
    with open(filename, 'w') as fp:
        for line in strList:
            print(line, file=fp)
    print("EffectiveStrings results are output to the file...")

def printTargetNode(node, name, filename, indent=0):
    if node.name == name:
        with open(filename, 'a') as fp:
            print(' ' * indent + node.name, file=fp)
        for child in node.children:
            printTargetNode(child, child.name, filename, indent + 4)
    else:
        for child in node.children:
            printTargetNode(child, name, filename, indent)

def createTree(data, fileDir):
    root = Node('WPeace-HcH')
    nodes = {}
    for key in data.keys():
        if key in nodes:
            parent_node = nodes[key]
        else:
            parent_node = Node(key, parent=root)
            nodes[key] = parent_node
        for value in data[key]:
            if value in nodes and nodes[value].parent is None:
                child_node = nodes[value]
                child_node.parent = parent_node
            else:
                child_node = Node(value, parent=parent_node)
                nodes[value] = child_node
    funcTree_filename = fileDir + "funcTree.txt"
    with open(funcTree_filename, 'w') as fp:
        for pre, fill, node in RenderTree(root):
            print("%s%s" % (pre, node.name), file=fp)
    mainFuncTree_filename = fileDir + "mainFuncTree.txt"
    with open(mainFuncTree_filename, 'w') as fp:
        pass
    printTargetNode(root, 'main', mainFuncTree_filename)

def getCallRelation(outputFileDir):
    startAddr = idc.get_name_ea_simple("_start")
    if startAddr == 0xffffffff or startAddr == 0xffffffffffffffff:
        startAddr = idc.get_name_ea_simple("__start")
        if startAddr == 0xffffffff or startAddr == 0xffffffffffffffff:
            startAddr = idc.get_name_ea_simple("start")
    if startAddr == 0xffffffff or startAddr == 0xffffffffffffffff:
        startAddr = idc.get_segm_by_sel(idc.selector_by_name(".text"))
    if startAddr == 0xffffffff or startAddr == 0xffffffffffffffff:
        print("Get startAddress failed. @WPeace")
        return 0
    funcDict = defaultdict(list)
    for function_ea in idautils.Functions(idc.get_segm_start(startAddr), idc.get_segm_end(startAddr)):
        funcName = idc.get_func_name(function_ea)
        if len(re.findall("^__.*", funcName)) != 0 or funcName == "syscall" or funcName == "start" or '@' in funcName or '?' in funcName:
            continue
        for ref_ea in idautils.CodeRefsTo(function_ea, 0):
            callerFunc = idc.get_func_name(ref_ea)
            if len(re.findall("^__.*", callerFunc)) == 0 and callerFunc != "" and '@' not in callerFunc and '?' not in callerFunc:
                funcDict[callerFunc].append(funcName)
    for callerFunc in funcDict:
        funcDict[callerFunc] = list(set(funcDict[callerFunc]))
    createTree(funcDict, outputFileDir)
    print("FuncTree results are output to the file...")

def main():
    outputFileDir = makeDir()
    getCallRelation(outputFileDir)
    getStrings(outputFileDir)

if __name__ == "__main__":
    main()

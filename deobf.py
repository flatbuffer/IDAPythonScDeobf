import re

import idautils
import idc
import idaapi

# idautils.Entries      Returns a list of entry points
# idautils.XrefsTo      Return all references to address 'ea'

# idc.MakeComm          To create comment at an address.
# idc.Comment           To read comment at an address.
# idc.GetDisasm         PUSH            {R4-R7,LR}
# idc.GetMnem           PUSH
# idc.GetOpnd                           {R4-R7,LR}

regex_mov = re.compile('MOV +PC, R[0-9]')


def search_forward(addr, addr_end, regexp):
    while True:
        asm = idc.GetDisasm(addr)
        if regexp.match(asm):
            return addr
        addr = idc.NextHead(addr, addr_end)
        if addr == idc.BADADDR:
            return None


def deobfuscate_function(addr):
    if addr != idc.FirstFuncFchunk(addr):
        print "[DEOBF] Address 0x%x is not the start of a function." % addr
        return

    func_start = addr
    func_end = idc.FindFuncEnd(addr)

    messy = search_forward(func_start, func_end, regex_mov)

    if messy is not None:
        print "Messy at 0x%x" % messy


# for func in idautils.Functions():
#     TODO: Deobf all the functions.

for entry in idautils.Entries():
    if entry[3] == "JNI_OnLoad":
        print "[DEOBF] Found JNI_OnLoad at 0x%x." % entry[2]
        deobfuscate_function(entry[2])

print "[DEOBF] Finished."

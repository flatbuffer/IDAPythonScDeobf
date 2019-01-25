import re
import json

import idautils
import idc

# idautils.Entries      Returns a list of entry points
# idautils.XrefsTo      Return all references to address 'ea'

# idc.MakeComm          To create comment at an address.
# idc.Comment           To read comment at an address.
# idc.GetDisasm         PUSH            {R4-R7,LR}
# idc.GetMnem           PUSH
# idc.GetOpnd                           {R4-R7,LR}

regex_mov = re.compile('MOV +PC, (R[0-9]+)')
regex_ldrw = re.compile('LDR\\.W +(R[0-9]+), \\[(R[0-9]+),(R[0-9]+),(LSL#2)\\]')
regex_table = re.compile('ADD +(R[0-9]+), PC; (.*?)$')


def search(next_addr, addr, addr_end, regexp):
    while True:
        asm = idc.GetDisasm(addr)
        asm_match = regexp.match(asm)
        if asm_match:
            return addr, asm_match
        addr = next_addr(addr, addr_end)
        if addr == idc.BADADDR:
            return None, None


def search_forward(addr, addr_end, regexp):
    return search(idc.NextHead, addr, addr_end, regexp)


def search_backward(addr, addr_end, regexp):
    return search(idc.PrevHead, addr, addr_end, regexp)


def search_register_modifier(next_addr, addr, addr_end, register):
    while True:
        if idc.GetOpnd(addr, 0) == register:
            return addr
        addr = next_addr(addr, addr_end)
        if addr == idc.BADADDR:
            return None


def search_register_modifier_forward(addr, addr_end, register):
    return search_register_modifier(idc.NextHead, addr, addr_end, register)


def search_register_modifier_backward(addr, addr_end, register):
    return search_register_modifier(idc.PrevHead, addr, addr_end, register)


def name_to_address(name):
    for ida_name in idautils.Names():
        if ida_name[1] == name:
            return ida_name[0]

    return None


def xrefs_count(ea):
    count = 0
    for _ in idautils.XrefsTo(ea):
        count += 1
    return count


def deobfuscate_function(addr):
    if addr != idc.FirstFuncFchunk(addr):
        print "[DEOBF] Address %X is not the start of a function." % addr
        return

    # Static data.
    func_start = addr
    func_end = idc.FindFuncEnd(addr)

    # 1. Find MOV PC
    (mov_addr, mov_match) = search_forward(func_start, func_end, regex_mov)

    if mov_addr is None:
        # print "[DEOBF] No MOV PC was found in %s" % idc.GetFunctionName(func_start)
        return

    # 2. Find LDR.W ..
    ldr_addr = search_register_modifier_backward(mov_addr, func_start, mov_match.group(1))
    ldr_match = regex_ldrw.match(idc.GetDisasm(ldr_addr)) if ldr_addr is not None else None

    if ldr_addr is None:
        print "[DEOBF] No LDR.W was found in %s" % idc.GetFunctionName(func_start)
        return

    if ldr_match is None:
        print "[DEOBF] Modifier of %s found from %X is not a LDR.W" % (mov_match.group(1), mov_addr)
        return

    # 3. Find table offset
    add_addr = search_register_modifier_backward(ldr_addr, func_start, ldr_match.group(2))
    # add_match = regex_table.match(idc.GetDisasm(add_addr)) if add_addr is not None else None
    #
    # print idc.GetEnum(add_match.group(2) + 'asd')

    if add_addr is None:
        # TODO: Check if belongs to a previously found graph.
        # print "[DEOBF] No ADD was found above %X" % ldr_addr
        return

    if idc.GetOpnd(add_addr, 1) != 'PC':
        print "[DEOBF] ADD does not use PC at %X" % add_addr
        return

    ldr2_addr = search_register_modifier_backward(idc.PrevHead(add_addr), func_start, idc.GetOpnd(add_addr, 0))

    opp_val = idc.GetOperandValue(ldr2_addr, 1)     # Address to loc_80054
    opp_val = idc.Dword(opp_val)                    # loc_80054
    opp_val = opp_val + idc.NextHead(add_addr) + 2  # Address of the table.

    # 4. Read table.
    table = []
    table_addr = opp_val

    while True:
        table_entry = idc.Dword(table_addr)
        if table_entry > 0:
            table.append(table_entry)
        table_addr = table_addr + 4
        if xrefs_count(table_addr) > 0:
            break

    # TODO: 5. Find subroutine boundary

    # TODO: 6. Iterate through the table


print "[DEOBF] ===================================="

# for func in idautils.Functions():
#     # TODO: Deobf all the functions.
#     deobfuscate_function(func)

# for entry in idautils.Entries():
#     if entry[3] == "JNI_OnLoad" or entry[3] == "sub_F3C4" or entry[3] == "sub_F580":
#         print "[DEOBF] Found JNI_OnLoad at %X" % entry[2]
#         deobfuscate_function(entry[2])

deobfuscate_function(0x24B24)  # JNI_OnLoad
# deobfuscate_function(0xF3C4)
# deobfuscate_function(0xF580)

print "[DEOBF] Finished."

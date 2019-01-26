import re
import json

import idaapi
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


def find_subroutine_boundary(table_addr, table):
    # Find all basic blocks.
    ranges = set()
    ida_functions = set()  # Storing all functions found so we can use it to verify results later.

    # Find all functions and blocks from the table.
    for entry in table:
        ida_func = idaapi.get_func(entry)
        ida_functions.add(ida_func.start_ea)

        ida_fc = idaapi.FlowChart(ida_func)
        ida_block = None

        # Find the block that belongs to this table entry.
        for ida_block_entry in ida_fc:
            if ida_block_entry.start_ea == entry:
                ida_block = ida_block_entry
                break

        if ida_block is None:
            print "[DEOBF] Unable to find block of %X" % entry
            return None, None

        brange = (ida_block.start_ea, ida_block.end_ea)

        if brange in ranges:
            print "[DEOBF] Found duplicate block usage at %X" % entry
            return None, None

        ranges.add(brange)

    # Make sure that every block of every function is found and in the table.
    miss_count = 0

    for ida_function in ida_functions:
        for ida_block in idaapi.FlowChart(idaapi.get_func(ida_function)):
            # Check if this block is in the table.
            found = False

            for brange in ranges:
                if brange[0] == ida_block.start_ea:
                    found = True
                    break

            if not found:
                if miss_count == 0 \
                        and ida_block.end_ea - ida_block.start_ea == 4\
                        and idc.GetMnem(ida_block.start_ea) == 'BLX':
                    print "[DEOBF] Found unimportant block at %X in table %X" % (ida_block.start_ea, table_addr)
                    miss_count += 1
                    continue

                print "[DEOBF] Found unused block at %X in table %X" % (ida_block.start_ea, table_addr)
                return None, None

    # Make sure every function connects.
    sub_start = None
    sub_end = None

    if len(ida_functions) > 1:
        for func_a in ida_functions:
            found_connection = False
            ida_func_a = idaapi.get_func(func_a)

            if sub_start is None or sub_start > ida_func_a.start_ea:
                sub_start = ida_func_a.start_ea

            if sub_end is None or sub_end < ida_func_a.end_ea:
                sub_end = ida_func_a.end_ea

            for func_b in ida_functions:
                ida_func_b = idaapi.get_func(func_b)

                if ida_func_a.start_ea == ida_func_b.end_ea \
                        or ida_func_a.end_ea == ida_func_b.start_ea:
                    found_connection = True
                    break
            if not found_connection:
                print "[DEOBF] Found disconnected function %X in table %X" % (ida_func_a.start_ea, table_addr)
                return None, None
    else:
        ida_func = idaapi.get_func(list(ida_functions)[0])
        sub_start = ida_func.start_ea
        sub_end = ida_func.end_ea

    return sub_start, sub_end


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
        if idc.Name(table_addr):
            break

    # - We also have to add the starting block to the table.
    table.append(func_start)

    # 5. Find subroutine boundary
    (sub_start, sub_end) = find_subroutine_boundary(opp_val, table)

    print "Start: %X - End: %X" % (sub_start, sub_end)

    # TODO: 6. Iterate through the table


print "[DEOBF] ===================================="

# for func in idautils.Functions():
#     # TODO: Deobf all the functions.
#     deobfuscate_function(func)

# for entry in idautils.Entries():
#     if entry[3] == "JNI_OnLoad" or entry[3] == "sub_F3C4" or entry[3] == "sub_F580":
#         print "[DEOBF] Found JNI_OnLoad at %X" % entry[2]
#         deobfuscate_function(entry[2])

# for ida_block in idaapi.FlowChart(idaapi.get_func(0x24B24)):
#     print "%X - %X" % (ida_block.start_ea, ida_block.end_ea)

deobfuscate_function(0x24B24)  # JNI_OnLoad
# deobfuscate_function(0xF3C4)
# deobfuscate_function(0xF580)

print "[DEOBF] Finished."

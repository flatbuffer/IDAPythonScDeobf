import re

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
regex_table = re.compile('ADD +(R[0-9]+), PC')


def search(search_method, addr, addr_end, regexp):
    while True:
        asm = idc.GetDisasm(addr)
        asm_match = regexp.match(asm)
        if regexp.match(asm):
            return addr, asm_match
        addr = search_method(addr, addr_end)
        if addr == idc.BADADDR:
            return None, None


def search_forward(addr, addr_end, regexp):
    return search(idc.NextHead, addr, addr_end, regexp)


def search_backward(addr, addr_end, regexp):
    return search(idc.PrevHead, addr, addr_end, regexp)


def deobfuscate_function(addr):
    if addr != idc.FirstFuncFchunk(addr):
        print "[DEOBF] Address %X is not the start of a function." % addr
        return

    # Static data.
    func_start = addr
    func_end = idc.FindFuncEnd(addr)

    # Identified by first.
    is_first = True
    state_register = None

    # Changes.
    current_addr = addr

    # TODO: "Rewrite"
    #   1 Find MOV PC ..
    #   2 Find LDR.W ..
    #   3 Find table offset
    #   4 Find subroutine boundary
    #   5 Iterate through the table

    # Need to make sure that all the subs connect to each other with nothing inbetween.

    while True:
        # Search for the next mov instruction that changes PC.
        (mov_addr, mov_match) = search_forward(current_addr, func_end, regex_mov)

        if mov_addr is None:
            if not is_first:
                print "[DEOBF] No more messy stuff in function %s" % idc.GetFunctionName(func_start)
            break

        # print "[DEOBF] Messy at 0x%x" % mov_addr

        # Parse state information.
        (state_addr, state_match) = search_backward(mov_addr, func_start, regex_ldrw)

        if state_match is None:
            print "[DEOBF] Failed to find state at %X" % mov_addr
            break

        # Verify state information.
        if is_first:
            is_first = False
            state_register = state_match.group(2)
            (table_addr, table_match) = search_backward(state_addr, func_start, regex_table)
            # Verify table.

        elif state_register != state_match.group(2):
            print "[DEOBF] state_register mismatch (%s!=%s) at %X" % (state_register, state_match.group(2), mov_addr)
            break

        # Verify state belongs to mov.
        if state_match.group(1) != mov_match.group(1):
            print "[DEOBF] mov & state mismatch (%s!=%s) at %X" % (state_match.group(1), state_match.group(1), mov_addr)
            break

        # Calculate destination.
        calced_addr = 0

        idc.MakeComm(mov_addr, 'Should jump to %X' % calced_addr)

        # Keep looking.
        # TODO: Conditional / branch properly. Should propably turn this while loop into a recursive function.
        current_addr = idc.NextHead(mov_addr)


print "[DEOBF] ===================================="

# for func in idautils.Functions():
#     # TODO: Deobf all the functions.
#     deobfuscate_function(func)

for entry in idautils.Entries():
    if entry[3] == "JNI_OnLoad":
        print "[DEOBF] Found JNI_OnLoad at %X" % entry[2]
        deobfuscate_function(entry[2])

print "[DEOBF] Finished."

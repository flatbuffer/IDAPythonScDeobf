# IDAPythonScDeobf

An IDAPython script to deobfuscate an ARMv7 library of a popular mobile app.  
This is a work in progress and my first attempt at an IDAPython script.

## Obfuscation

These are all obfuscation methods found in the library.  
This is not final.

### Control Flow Flattening

![Control Flow Flattening Image](docs/cff.png)

The state machine initializes like this.

```assembly
# Snip
ADD     R4, PC ; off_A4BE0
# Snip
MOVCC   R0, #9
LDR.W   R0, [R4,R0,LSL#2]
# Snip
MOV     PC, R0
# Sub chunks below..
```

The offset `off_XXXXX` holds a table containing all the blocks that probably belong to the original subroutine.

```
off_A4BE0       DCD loc_24BB4
                DCD loc_24C5E
                DCD loc_24CC2
                DCD sub_24D3A
                DCD loc_24BFA
                DCD loc_24D04
                DCD loc_24C2C
                DCD loc_24CD6
                DCD loc_24BE6
                DCD loc_24D26
                DCD loc_24C90
                DCD loc_24CEA
                DCD loc_24BA0
```

We can use this information to figure out the subroutine boundaries and reconstruct the control flow between those.
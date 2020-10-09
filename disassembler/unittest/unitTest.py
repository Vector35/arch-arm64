#!/usr/bin/env python

import re
import os, sys, subprocess
import struct
from ctypes import *
from capstone import *
import test

disasmBuff = create_string_buffer(1024)
instBuff =   create_string_buffer(1024)
binja = CDLL("./arm64dis.so")
md = Cs(CS_ARCH_ARM64, CS_MODE_ARM)

def disassemble_binja(instruction):
#    instruction = instruction[::-1]
    for a in range(len(disasmBuff)):
        disasmBuff[a] = b'\0'
    for a in range(len(instBuff)):
        instBuff[a] = b'\0'

    err = binja.aarch64_decompose(struct.unpack("<L", instruction)[0], instBuff, 0)
    if err == 1:
        return "decomposer failed"
    elif err == 2:
        return "group decomposition failed"
    elif err == 3:
        return "unimplemented"

    if binja.aarch64_disassemble(instBuff, disasmBuff, 128) == 0:
        return disasmBuff.value.decode('utf-8')

    return "disassembly failed"

def disassemble_capstone(instruction):
    for a in md.disasm(instruction, 0):
        return a.mnemonic + "\t" + a.op_str

def areEqual(binja, capstone):
    capstone = capstone.strip()
    if binja == capstone:
        return True

    belms = re.findall(r"[^ \]\[,\t]+", binja)
    celms = re.findall(r"[^ \]\[,\t]+", capstone)
    if len(belms) == 0 and len(celms) != 0:
        return False

    for i,a in enumerate(celms):
        b = a
        if b.startswith("0x"):
            if b[-1] == "L":
                b = b[:-1]
            celms[i] = "%d" % int(b, 16)

    def tohex(val, nbits):
          return hex((val + (1 << nbits)) % (1 << nbits))

    #normalize capstons ORR-> MOV missing alias
    if len(celms) > 2 and celms[0] == "orr" and belms[0] == "mov" and celms[2].endswith("zr"):
        celms[0] = "mov"
        del celms[2]

    #fix capstones broken shifted neg stuff
    if (celms[0] == "subs" and belms[0] == "negs") or (celms[0] == "sub" and belms[0] == "neg" ) and "zr" in celms[2]:
        del celms[2]
        del celms[0]
        del belms[0]
        if belms[-2] in ("lsl", "lsr"):
            if belms[-1] == "#0x0":
                del belms[-1]
                del belms[-1]
        if celms[-2] in ("lsl", "lsr"):
            if celms[-1] == "#0":
                del celms[-1]
                del celms[-1]
    #fix capstone broken mov aliases
    if belms[0] == "mov":
        if celms[0] == "movz":
            if celms[-2] == "lsl":
                shift = int(celms[-1][1:], 10)
                imm =  int(celms[-3][1:], 16)
                celms[-3] = "#" + hex(imm<<shift)
                del celms[-1]
                del celms[-1]
            celms[0] = belms[0]
        elif celms[0] == "movn":
            size = 32
            if celms[1][0] == "x":
                size = 64
            if len(celms) == 5 and len(belms) == 3:
                celms[2] = tohex(~(int(celms[2][1:], 16)<<int(celms[-1][1:])),size)
                belms[-1] = tohex(int(belms[-1][1:],16), size)
                del celms[-1]
                del celms[-1]
            else:
                celms[-1] = tohex(~int(celms[-1][1:], 16),size)
                belms[-1] = tohex(int(belms[-1][1:],16), size)
            celms[0] = belms[0]

    for i in range(len(celms)):
        if celms[i] == "hs":
            celms[i] = "cs"
        elif celms[i] == "lo":
            celms[i] = "cc"
    #capstone(llvm) implements a specific trace register
    #feature that I haven't been able to find so just
    #delete the argument that doesn't match
    if belms[0] == "msr":
        if len(belms) < 3 or len(celms) < 3 or belms[1] == "NONE":
            return False
        del belms[1]
        del celms[1]

    if belms[0] == "mrs":
        if len(belms) < 3 or len(celms) < 3 or belms[-1] == "NONE":
            return False
        del belms[-1]
        del celms[-1]

    if len(belms) != len(celms):
        return False
    for b,c in zip(belms, celms):
        if b == c:
            continue
        #normalize conditional branches
        if b.startswith("b.") and c.startswith("b."):
            bend = b[2:]
            cend = c[2:]
            if bend in ("cs", "hs") and cend in ("cs", "hs"):
                return True
            if bend in ("cc", "lo") and cend in ("cc", "lo"):
                return True
            return False

        #normalize and compare integers
        elif len(c) > 1 and len(b) > 1 and c[0] == "#" and b[0] == "#":
            #ok they are both immediates but maybe their encoding is bad

            c1 = c[1:]
            b1 = b[1:]
            if c1.endswith("lu"):
                c1 = c1[:-2]
            if c1.endswith("l"):
                c1 = c1[:-1]

            isFloat = False
            if "0x" in c1:
                if c1[-1] == "L":
                    c1 = c1[:-1]

                if len(c1) <= 2:
                    return False
                c1 = int(c1, 16)
            elif "." in c1:
                c1 = float(c1)
                isFloat = True
            else:
                c1 = int(c1, 10)

            if "0x" in b1:
                if b1[-1] == "L":
                    b1 = b1[:-1]
                if len(b1) <= 2:
                    return False
                b1 = int(b1, 16)
            elif "." in b1:
                b1 = float(b1)
                isFloat = True
            else:
                b1 = int(b1, 10)

            if not isFloat:
                c1 = c1 & 0xffffffffffffffff
                b1 = b1 & 0xffffffffffffffff
                #because capstone is dumb and doesn't respect the call for using a singed number sometimes :(
                if bin(c1)[2:1] == 1:
                    c1 = (-c1)-1
                if bin(b1)[2:1] == 1:
                    b1 = (-b1)-1
            return c1 == b1
        else:
            return False

    #white space difference?
    return True

usage = "%s [-v] [-f <arm64File>] [-b] [-u <unitTestFile>] [<32-bitValue>]" % sys.argv[0]
def main():
    if len(sys.argv) < 2:
        print(usage)
        return

    instructions = []
    verbose = 0
    if sys.argv[1] == "-v":
        verbose = 1
        sys.argv = sys.argv[1:]
    if sys.argv[1] == "-vv":
        verbose = 2
        sys.argv = sys.argv[1:]
    if sys.argv[1] == "-f":
        if len(sys.argv) < 3:
            print(usage)
            return
        tmp = open(sys.argv[2], 'rb').read()
        if len(tmp) % 4 != 0:
            print("File must be multiple of 4")
            return
        for a in range(0, len(tmp), 4):
            instructions.append(tmp[a:a+4])
    elif sys.argv[1] == "-t":
        for a in test.tests:
            instructions.extend(struct.pack("<L",a))
    elif sys.argv[1] == "-u":
        lines = open(sys.argv[2]).read().split("\n")
        for line in lines:
            if line.startswith("#") or len(line) == 0:
                continue
            hexvalues, disasm = line.split(" = ")
            instructions.append( b''.join([x.to_bytes(1,'big') for x in eval(hexvalues)]) )

    else:
        try:
            instructions.append(struct.pack("<L",int(sys.argv[1], 16)))
        except:
            print("Failed to parse 32-bit hex value %s" % sys.argv[1])
            return

    errors = 0
    success = 0
    f = open('errors.bin', 'wb')
    undefined = {}
    for instruction in instructions:
        binja = disassemble_binja(instruction)
        capstone = disassemble_capstone(instruction)
        if verbose > 1:
            print("binja:", binja)
            print("capst:", capstone)
        if binja == "unimplemented":
            if capstone is not None:
                opcode = capstone.split('\t')[0]
                if opcode not in undefined.keys():
                    undefined[opcode] = 1
                else:
                    undefined[opcode] += 1
            continue
        if (binja is not None and capstone is not None and not areEqual(binja, capstone)):
            if "UNDEFINED" in binja or "failed" in binja:
                if capstone is not None:
                    opcode = capstone.split('\t')[0]
                    if opcode not in undefined.keys():
                        undefined[opcode] = 1
                    else:
                        undefined[opcode] += 1
                    errors += 1
                    print("ERROR: Oracle: %s '%s'\n       You:    %s '%s'" % (instruction.hex(), capstone, instruction.hex(), binja))
                    f.write(instruction)
            else:
                print("ERROR: Oracle: %s '%s'\n       You:    %s '%s'" % (instruction.hex(), capstone, instruction.hex(), binja))
                errors += 1
                f.write(instruction)
        else:
            success += 1
    print("%d errors, %d successes, %d test cases success percentage %%%.2f" % (errors, success, len(instructions), (float(success)/float(len(instructions))) * 100.0))

    print("%d undefined instructions" % len(undefined))
    if verbose:
        import operator
        sorted_undefined = sorted(undefined.items(), key=operator.itemgetter(1))
        for a,b in sorted_undefined:
            print("%s\t%d" % (a, b))

if __name__ == "__main__":
    main()

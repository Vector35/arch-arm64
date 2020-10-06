#!/usr/bin/env python

# This tester does NOT use an oracle at runtime to verify disassembly. Instead,
# it does an absolute comparison to what's in the given test file. See
# mteInstruction.txt for an example.

import re
import os, sys, subprocess
import struct
from ctypes import *

RED = '\x1B[31m'
GREEN = '\x1B[32m'
NORMAL = '\x1B[0m'

disasmBuff = create_string_buffer(1024)
instBuff = create_string_buffer(1024)
binja = CDLL("./arm64dis.so")

def disassemble_binja(insnum):
	instruction = struct.pack('<I', insnum)
	for a in range(len(disasmBuff)):
		disasmBuff[a] = b'\0'
	for a in range(len(instBuff)):
		instBuff[a] = b'\0'
	err = binja.aarch64_decompose(struct.unpack("<L", instruction)[0], instBuff, 0)
	if err == 1: return "decomposer failed"
	elif err == 2: return "group decomposition failed"
	elif err == 3: return "unimplemented"
	if binja.aarch64_disassemble(instBuff, disasmBuff, 128) == 0:
		tmp = disasmBuff.value.decode('utf-8')
		return re.sub(r'\s+', ' ', tmp)
	return "disassembly failed"

if __name__ == '__main__':
	fpath_test = sys.argv[1]
	with open(fpath_test) as fp:
		(passes, failures) = (0, 0)
		for (i,line) in enumerate(fp.readlines()):
			line = line.strip()
			if not line: continue
			if line.startswith('#'): continue
			if line.isspace(): continue
			m = re.match(r'^(........) (.+)$', line)
			assert m, "malformed test case at line %d" % (i+1)
			insnum = int(m.group(1), 16)
			instxt = m.group(2)
			test = disassemble_binja(insnum)
			print('%08X: %s%s ' % (insnum, test.ljust(48), instxt), end='')
			if test==instxt:
				print(GREEN + "pass" + NORMAL)
				passes += 1
			else:
				print(RED + "FAIL" + NORMAL)
				failures += 1
	print('%d successes, %d failures, %.2f%% pass rate' % \
		(passes, failures, passes/(passes+failures)*100))

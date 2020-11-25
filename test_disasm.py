#!/usr/bin/env python

import re, struct, os, sys, ctypes

import binaryninja
print("binaryninja.__file__:", binaryninja.__file__)

sys.path.append('./disassembler')
import disasm_test


arch = None
def disassemble(insnum):
	global arch
	if not arch:
		arch = binaryninja.Architecture['aarch64']
	data = struct.pack('<I', insnum)
	(tokens, length) = arch.get_instruction_text(data, 0)
	if not tokens or length==0:
		return None
	return ''.join([x.text for x in tokens])

def main():
	if sys.argv[1:]:
		insnum = int(sys.argv[1], 16)
		print(disassemble(insnum))

	else:
		with open('./disassembler/test_cases.txt') as fp:
			lines = fp.readlines()

		for (i,line) in enumerate(lines):
			if line.startswith('// '): continue
			assert line[8] == ' '
			insnum = int(line[0:8], 16)
			actual = disassemble(insnum)
			expected = line[9:].rstrip()
			print('0x%08X %s    vs.    %s' % (insnum, actual, expected))
			if disasm_test.compare_disassembly(actual, expected):
				if actual and disasm_test.excusable_difference(actual, expected):
					continue
				print('line %d/%d (%.2f%%)' % (i, len(lines), i/len(lines)*100))
				sys.exit(-1)

		print('PASS')

if __name__ == '__main__':
	main()

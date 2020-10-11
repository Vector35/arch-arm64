#!/usr/bin/env python

test_cases = [
	(b'\x0a\x00\x80\x52', 'LLIL_SET_REG(w10,LLIL_CONST(0))'), # mov 10, #0
]

import sys
import binaryninja
from binaryninja import core
from binaryninja import binaryview
from binaryninja import lowlevelil

def il2str(il):
	if isinstance(il, lowlevelil.LowLevelILInstruction):
		return '%s(%s)' % (il.operation.name, ','.join([il2str(o) for o in il.operands]))
	else:
		return str(il)

def instr_to_il(data):
	platform = binaryninja.Platform['linux-aarch64']
	bv = binaryview.BinaryView.new(data)
	bv.add_function(0, plat=platform)
	assert len(bv.functions) == 1

	result = ''
	for block in bv.functions[0].low_level_il:
		for il in block:
			return il2str(il)

for (test_i, (data, expected)) in enumerate(test_cases):
	actual = instr_to_il(data)
	if actual != expected:
		print('MISMATCH AT TEST %d!' % test_i)
		print('\texpected: %s' % expected)
		print('\t  actual: %s' % actual)
		sys.exit(-1)

	print('success!')
	sys.exit(0)

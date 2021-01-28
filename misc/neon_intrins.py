#!/usr/bin/env python
# read neon_intrins.c and generate code for the architecture

import re
import sys

# SMMLA Vd.4S,Vn.16B,Vm.16B -> Vd.4S
def get_destination_reg(asig):
	try:
		(mnem, regs) = re.match(r'^(\w+) (.*)', asig).group(1,2)
	except AttributeError:
		print('couldn\'t get destination register from -%s-' % asig)
		sys.exit(-1)
	return regs.split(',')[0]

def get_reg_size(reg):
	if reg in ['Qd', 'Qt']: return 16
	if reg in ['Dd', 'Dm']: return 8
	if reg=='Sd': return 4
	if reg=='Hd': return 2
	if reg=='Bd': return 1

	if reg in ['Wd', 'Wn', 'Wm']: return 4

	reg = reg.lower()
	if '.1q' in reg: return 16
	if '.2d' in reg: return 16
	if '.4s' in reg: return 16
	if '.8h' in reg: return 16
	if '.16b' in reg: return 16
	if '.d' in reg: return 8
	if '.1d' in reg: return 8
	if '.2s' in reg: return 8
	if '.4h' in reg: return 8
	if '.8b' in reg: return 8
	if '.s' in reg: return 4
	if '.2h' in reg: return 4
	if '.4b' in reg: return 4
	if '.h' in reg: return 2
	if '.b' in reg: return 1

	print('couldn\'t get size of register -%s-' % reg)
	sys.exit(-1)

def get_write_size(asig):
	(mnem, regs) = re.match(r'^(\w+) (.*)', asig).group(1,2)
	regs = regs.split(',')
	reg0 = regs[0]

	if reg0=='Rd':
		# eg: UMOV Rd,Vn.B[lane] means Rd is 1 byte
		assert len(regs)==2
		return get_reg_size(regs[1])

	if reg0.startswith('{') and reg0.endswith('}') and ' - ' in reg0:
		# eg: ST2 {Vt.16B - Vt2.16B},[Xn]
		m = re.match('^.* - (Vt(\d)\..*)}', reg0)
		(reg0, num) = m.group(1,2)
		return (int(num)+1) * get_reg_size(reg0)

	return get_reg_size(reg0)

with open('neon_intrins.c') as fp:
	lines = [l.strip() for l in fp.readlines()]

seen = set()
intrin_defines = [] # parallel arrays to maintain order from all_neon_intrinsics.c
intrin_names = []
intrin_asigs = []

for l in lines:
	if 'reinterpret' in l: continue
	(fsig, asig) = l.split('; // ')

	m = re.match(r'^\w+ (\w+)\(.', fsig)
	fname = m.group(1)

	if fname in seen:
		continue
	else:
		seen.add(fname)

	#print('-%s- -%s- -%s-' % (fsig, fname, asig))
	intrin_defines.append('ARM64_INTRIN_%s' % fname.upper())
	intrin_names.append(fname)
	if asig.startswith('RESULT['): asig = None # array-like looping not yet supported
	intrin_asigs.append(asig)

if sys.argv[1] in ['enum', 'enumeration']:
	# for enum NeonIntrinsic : uint32_t ...
	for x in intrin_defines:
		extra = '=ARM64_INTRIN_NORMAL_END' if x==intrin_defines[0] else ''
		print('\t%s%s,' % (x, extra))

elif sys.argv[1] in ['name', 'names']:
	# for GetIntrinsicName(uint32_t intrinsic)
	for i in range(len(intrin_defines)):
		print('\t\tcase %s: return "%s";' % (intrin_defines[i], intrin_names[i]))

elif sys.argv[1] in ['all', 'define', 'defines']:
	# for GetAllIntrinsics()
	i = 0
	while i<len(intrin_defines):
		print('\t\t' + ', '.join(intrin_defines[i:i+3]) + ',')
		i += 3

elif sys.argv[1] in ['input', 'inputs']:
	pass

elif sys.argv[1] in ['output', 'outputs']:
	size_to_cases = {}

	# for GetIntrinsicOutputs()
	for i in range(len(intrin_defines)):
		asig = intrin_asigs[i]
		if not asig: continue
		reg_dest = get_destination_reg(asig)
		wsize = get_write_size(asig)

		if not wsize in size_to_cases:
			size_to_cases[wsize] = []

		#size_to_cases[wsize].append('case %s: // writes %s (%d bytes)' % (intrin_defines[i], reg_dest, wsize))
		size_to_cases[wsize].append('case %s:' % intrin_defines[i])

	for size in sorted(size_to_cases):
		for case in size_to_cases[size]:
			print('\t\t%s' % case)

		print('\t\t\treturn {Type::IntegerType(%d, false)};' % size)

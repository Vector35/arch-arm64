#!/usr/bin/env python
# read neon_intrins.c and generate code for the architecture

import re
import sys

from collections import OrderedDict

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

if __name__ == '__main__':
	# parse neon_intrins.c into a "database"
	with open('neon_intrins.c') as fp:
		lines = [l.strip() for l in fp.readlines()]

	db = OrderedDict()

	for l in lines:
		if 'reinterpret' in l: continue
		(fsig, asig) = l.split('; // ')

		m = re.match(r'^(\w+) (\w+)\(.', fsig)
		(rtype, fname) = m.group(1, 2)
		if fname in db: continue

		args = re.match(r'^\w+ \w+\((.*)\)$', fsig).group(1).split(', ')
		args = [re.match(r'^(.*) \w+$', arg).group(1) for arg in args]
		args = [x[6:] if x.startswith('const ') else x for x in args]
		(write_type, read_types) = (None, None)
		if rtype == 'void':
			assert 'st' in fname and 'ST' in asig and '*' in args[0]
			write_type = args[0]
			read_types = args[1:]
		else:
			write_type = rtype
			read_types = args

		skip = asig.startswith('RESULT[') # array-like looping not yet supported

		db[fname] = { 'fsig': fsig,
		              'asig': asig,
		              'define': 'ARM64_INTRIN_%s' % fname.upper(),
		              'write_type': write_type,
		              'read_types': read_types,
		              'skip': skip}

	cmd = sys.argv[1]

	if cmd in ['dump']:
		import pprint
		pp = pprint.PrettyPrinter()
		pp.pprint(db)

	elif cmd in ['enum', 'enumeration']:
		# for enum NeonIntrinsic : uint32_t ...
		first = True
		for fname in db:
			extra = '=ARM64_INTRIN_NORMAL_END' if first else ''
			print('\t%s%s,' % (db[fname]['define'], extra))
			first = False

	elif cmd in ['name', 'names']:
		# for GetIntrinsicName(uint32_t intrinsic)
		for fname in db:
			print('\t\tcase %s: return "%s";' % (db[fname]['define'], fname))

	elif cmd in ['all', 'define', 'defines']:
		# for GetAllIntrinsics()
		collection = [db[fname]['define'] for fname in db]
		i = 0
		while i<len(collection):
			print('\t\t' + ', '.join(collection[i:i+3]) + ',')
			i += 3

	elif cmd in ['input', 'inputs']:
		pass

	elif cmd in ['output', 'outputs']:
		size_to_cases = {}

		# for GetIntrinsicOutputs()
		for i in range(len(intrin_defines)):
			asig = intrin_asigs[i]
			if not asig: continue

			fsig = intrin_
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

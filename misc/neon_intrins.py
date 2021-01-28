#!/usr/bin/env python
# read neon_intrins.c and generate code for the architecture

import re
import sys

with open('neon_intrins.c') as fp:
	lines = [l.strip() for l in fp.readlines()]

seen = set()
intrin_defines = [] # parallel arrays to maintain order from all_neon_intrinsics.c
intrin_names = []

for l in lines:
	if 'reinterpret' in l: continue
	(fsig, asig) = l.split('; // ')

	m = re.match(r'^\w+ (\w+)\(.', fsig)
	fname = m.group(1)

	if fname in seen:
		continue
	else:
		seen.add(fname)

	intrin_defines.append('ARM64_INTRIN_%s' % fname.upper())
	intrin_names.append(fname)
	
	#print('-%s- -%s- -%s-' % (fsig, fname, asig))

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
	pass



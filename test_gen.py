#!/usr/bin/env python

# utility to generate tests

import re, sys, codecs

from arm64test import instr_to_il, il2str
if not sys.argv[1:]:
	sys.exit(-1)

# generate lifting tests for a given mnemonic
# example:
# ./test_gen mnemonic ld1
if sys.argv[1] == 'mnemonic':
	N_SAMPLES = 2
	mnem = sys.argv[2]
	print('searching for mnemonic -%s-' % mnem)
	fpath = './disassembler/test_cases.txt'
	with open(fpath) as fp:
		lines = fp.readlines()

	encoding = ''
	samples = 0
	for line in lines:
		m = re.match(r'^// (.*) .*', line)
		if m:
			#print('encoding is now: %s' % encoding)
			encoding = m.group(1)
			samples = 0
			continue

		m = re.match(r'^(..)(..)(..)(..) (.*)', line)
		if m:
			if samples >= N_SAMPLES:
				continue
			(b0, b1, b2, b3, instxt) = m.group(1,2,3,4,5)
			data = codecs.decode(b3+b2+b1+b0, 'hex_codec')
			if not (instxt==mnem or instxt.startswith(mnem+' ')):
				continue
			#if samples == 0:
			#	print('\t# %s' % encoding)
			print('\t# %s ' % instxt)
			ilstr = instr_to_il(data)
			il_lines = ilstr.split(';')
			print('\t(b\'\\x%s\\x%s\\x%s\\x%s\', ' % (b3, b2, b1, b0), end='')
			for (i,line) in enumerate(il_lines):
				if i!=0:
					print('\t\t\t     ', end='')
				print(line, end='')
				if i!=len(il_lines)-1:
					print()
				
			print('),')
			samples += 1
			continue

		print('unable to parse line: %s' % line)
		sys.exit(-1)







// gcc -g test.c arm64dis.c -o test
// lldb ./test -- d503201f
// b aarch64_decompose
// b aarch64_disassemble
//
// gcc -ofast test.c aarch64.c -o test
// time ./test speed

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "arm64dis.h"

int main(int ac, char **av)
{
	uint32_t insword = strtoul(av[1], NULL, 16);
	uint32_t address = 0;
	uint32_t rc;

	Instruction instr;
	memset(&instr, 0, sizeof(instr));

	rc = aarch64_decompose(insword, &instr, address);
	if(rc) {
		printf("ERROR: aarch64_decompose() returned %d\n", rc);
		return rc;
	}

	char instxt[4096];
	memset(instxt, 0, sizeof(instxt));
	rc = aarch64_disassemble(&instr, instxt, sizeof(instxt));
	if(rc) {
		printf("ERROR: aarch64_disassemble() returned %d\n", rc);
		return rc;
	}

	printf("%08X: %s\n", address, instxt);
}


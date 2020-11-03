// gcc -g test.c arm64dis.c -o test
// lldb ./test -- d503201f
// b aarch64_decompose
// b aarch64_disassemble
//
// gcc -ofast test.c arm64dis.c -o test
// time ./test speed

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include "arm64dis.h"

int disassemble(uint64_t address, uint32_t insword, char *result)
{
	int rc;
	Instruction instr;
	memset(&instr, 0, sizeof(instr));

	rc = aarch64_decompose(insword, &instr, address);
	if(rc) {
		//printf("ERROR: aarch64_decompose() returned %d\n", rc);
		return rc;
	}

	rc = aarch64_disassemble(&instr, result, 1024);
	if(rc) {
		//printf("ERROR: aarch64_disassemble() returned %d\n", rc);
		return rc;
	}

	return 0;
}

int main(int ac, char **av)
{
	char instxt[1024];

	if(ac > 1 && !strcmp(av[1], "speed")) {
		srand(0xCAFE);
		for(int i=0; i<100000000; i++) {
			uint32_t insword = (rand() << 16) ^ rand();
			disassemble(0, insword, instxt);
			//printf("%08X: %s\n", insword, instxt);
		}
	}
	else {
		uint32_t insword = strtoul(av[1], NULL, 16);
		disassemble(0, insword, instxt);
		printf("%08X: %s\n", insword, instxt);
	}
}


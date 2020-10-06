#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <sys/stat.h>
#include "arm64dis.h"

int main()
{
	const char* fileName = "instructions.bin";
	uint32_t* buffer = NULL;
	struct stat statbuf;
	FILE* file = fopen(fileName, "rb");
	stat(fileName, &statbuf);
	uint32_t size = statbuf.st_size;
	buffer = malloc(size);
	if (buffer == NULL)
		return 1;

	uint32_t nread = 0;
	nread = fread(buffer,1,size, file);
	if (nread != size)
		return 1;

	Instruction inst;
	char disassemblyBuffer[256];
	for (uint32_t i = 0; i < size/sizeof(uint32_t); i++)
	{
		memset(&inst, 0, sizeof(inst));
		memset(disassemblyBuffer, 0, sizeof(disassemblyBuffer));
		aarch64_decompose(buffer[i], &inst, 0);
		if (aarch64_disassemble(&inst, disassemblyBuffer, sizeof(disassemblyBuffer)) == 0)
			printf("    %4x:\t%08x \t%s\n", i*4, buffer[i], disassemblyBuffer);
		else
			printf("    %4x:\t%08x \t%s\n", i*4, buffer[i], "disassembly failed");
	}
	return 0;
}

/* easy-to-debug tester
gcc -I.. -g ./test.c ../arm64dis.c -o test
lldb ./test
b aarch64_decompose
b aarch64_disassemble
r
*/

#include <stdio.h>
#include <stdint.h>
#include <string.h>

#include "arm64dis.h"

int main(int ac, char **av)
{
	//uint32_t insnum = 0x1f2003d5; // nop
	//uint32_t insnum = 0xd5184260; // msr PAN, x0
	//uint32_t insnum = 0x91B31474; // addg x20, x3, #816, #5
	//uint32_t insnum = 0x187fffe0; // ldr w0, #0xffffc
	//uint32_t insnum = 0x089ffffb; // ldarh w30, [x0]
	uint32_t insnum = 0xD96D0234;
	Instruction decoded;
	memset(&decoded, 0, sizeof(decoded));

	uint32_t rc = aarch64_decompose(insnum, &decoded, 0);
	if(rc == 0) {
		char insstr[128];
		memset(insstr, 0x41, 128);
		rc = aarch64_disassemble(&decoded, insstr, 128);
		if(rc == 0)
			printf("%s\n", insstr);
		else
			printf("ERROR: aarch64_disassemble() returned %u\n", rc);
	}
	else
		printf("ERROR: aarch64_disassemble() returned %u\n", rc);

	return 0;
}

/*
  lldb ./cmdline -- single d503201f
  b decode
  r
*/
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "decode.h"
#include "format.h"

int verbose = 1;

char* arrspec_to_str(enum ArrangementSpec as)
{
	switch (as)
	{
	case ARRSPEC_NONE:
		return "NONE";
	case ARRSPEC_FULL:
		return "FULL";
	case ARRSPEC_2DOUBLES:
		return "2DOUBLES";
	case ARRSPEC_4SINGLES:
		return "4SINGLES";
	case ARRSPEC_8HALVES:
		return "8HALVES";
	case ARRSPEC_16BYTES:
		return "16BYTES";
	case ARRSPEC_1DOUBLE:
		return "1DOUBLE";
	case ARRSPEC_2SINGLES:
		return "2SINGLES";
	case ARRSPEC_4HALVES:
		return "4HALVES";
	case ARRSPEC_8BYTES:
		return "8BYTES";
	case ARRSPEC_1SINGLE:
		return "1SINGLE";
	case ARRSPEC_2HALVES:
		return "2HALVES";
	case ARRSPEC_4BYTES:
		return "4BYTES";
	case ARRSPEC_1HALF:
		return "1HALF";
	case ARRSPEC_1BYTE:
		return "1BYTE";
	default:
		return "ERROR";
	}
}

char* oper_class_to_str(enum OperandClass c)
{
	switch (c)
	{
	case NONE:
		return "NONE";
	case IMM32:
		return "IMM32";
	case IMM64:
		return "IMM64";
	case FIMM32:
		return "FIMM32";
	case STR_IMM:
		return "STR_IMM";
	case REG:
		return "REG";
	case MULTI_REG:
		return "MULTI_REG";
	case SYS_REG:
		return "SYS_REG";
	case MEM_REG:
		return "MEM_REG";
	case MEM_PRE_IDX:
		return "MEM_PRE_IDX";
	case MEM_POST_IDX:
		return "MEM_POST_IDX";
	case MEM_OFFSET:
		return "MEM_OFFSET";
	case MEM_EXTENDED:
		return "MEM_EXTENDED";
	case SME_TILE:
		return "SME_TILE";
	case INDEXED_ELEMENT:
		return "INDEXED_ELEMENT";
	case ACCUM_ARRAY:
		return "ACCUM_ARRAY";
	case LABEL:
		return "LABEL";
	case CONDITION:
		return "CONDITION";
	case NAME:
		return "NAME";
	case IMPLEMENTATION_SPECIFIC:
		return "IMPLEMENTATION_SPECIFIC";
	default:
		return "ERROR";
	}
}

char* cond_to_str(enum Condition c)
{
	switch (c)
	{
	case COND_EQ:
		return "eq";
	case COND_NE:
		return "ne";
	case COND_CS:
		return "cs";
	case COND_CC:
		return "cc";
	case COND_MI:
		return "mi";
	case COND_PL:
		return "pl";
	case COND_VS:
		return "vs";
	case COND_VC:
		return "vc";
	case COND_HI:
		return "hi";
	case COND_LS:
		return "ls";
	case COND_GE:
		return "ge";
	case COND_LT:
		return "lt";
	case COND_GT:
		return "gt";
	case COND_LE:
		return "le";
	case COND_AL:
		return "al";
	case COND_NV:
		return "nv";
	default:
		return "ERROR";
	}
}

char* shifttype_to_str(enum ShiftType st)
{
	switch (st)
	{
	case ShiftType_NONE:
		return "ShiftType_NONE";
	case ShiftType_LSL:
		return "ShiftType_LSL";
	case ShiftType_LSR:
		return "ShiftType_LSR";
	case ShiftType_ASR:
		return "ShiftType_ASR";
	case ShiftType_ROR:
		return "ShiftType_ROR";
	case ShiftType_UXTW:
		return "ShiftType_UXTW";
	case ShiftType_SXTW:
		return "ShiftType_SXTW";
	case ShiftType_SXTX:
		return "ShiftType_SXTX";
	case ShiftType_UXTX:
		return "ShiftType_UXTX";
	case ShiftType_SXTB:
		return "ShiftType_SXTB";
	case ShiftType_SXTH:
		return "ShiftType_SXTH";
	case ShiftType_UXTH:
		return "ShiftType_UXTH";
	case ShiftType_UXTB:
		return "ShiftType_UXTB";
	case ShiftType_MSL:
		return "ShiftType_MSL";
	case ShiftType_END:
		return "ShiftType_END";
	default:
		return "ERROR";
	}
}

int disassemble(uint64_t address, uint32_t insword, char* result)
{
	int rc;
	Instruction instr;
	memset(&instr, 0, sizeof(instr));

	rc = aarch64_decompose(insword, &instr, address);
	if (verbose)
		printf("aarch64_decompose() returned %d\n", rc);
	if (rc)
		return rc;

	if (verbose)
	{
		printf("  instr.insword: %08X\n", instr.insword);
		printf(" instr.encoding: %d %s\n", instr.encoding, enc_to_str(instr.encoding));
		printf("instr.operation: %d %s\n", instr.operation, operation_to_str(instr.operation));
		printf(" instr.setflags: %d\n", instr.setflags);
		for (int i = 0; i < MAX_OPERANDS && instr.operands[i].operandClass != NONE; i++)
		{
			printf("instr.operands[%d]\n", i);

			InstructionOperand operand = instr.operands[i];

			/* class */
			printf("\t.class: %d (\"%s\")\n", operand.operandClass, oper_class_to_str(operand.operandClass));
			switch (operand.operandClass)
			{
			case CONDITION:
				printf("\t\t%d %s\n", operand.cond, cond_to_str(operand.cond));
				break;
			case FIMM32:
				printf("\t\t%f\n", *(float*)&(operand.immediate));
				break;
			case IMM32:
				printf("\t.imm32: 0x%llX\n", operand.immediate & 0xFFFFFFFF);
				break;
			case IMM64:
				printf("\t.imm64: 0x%llX\n", operand.immediate);
				break;
			case NAME:
				printf("\t.name: %s\n", operand.name);
				break;
			default:
				break;
			}
			/* lane */
			if (operand.laneUsed)
				printf("\t.lane: %d\n", operand.lane);
			/* shift */
			if (operand.shiftType != ShiftType_NONE)
			{
				printf("\t.shiftType: %d (%s)\n", operand.shiftType, shifttype_to_str(operand.shiftType));
			}
			/* arrangement spec */
			printf("\t.arrSpec: %d %s\n", operand.arrSpec, arrspec_to_str(operand.arrSpec));
		}
	}

	rc = aarch64_disassemble(&instr, result, 1024);
	if (verbose)
		printf("aarch64_disassemble() returned %d\n", rc);
	if (rc)
		return rc;

	return 0;
}

/* main */
int main(int ac, char** av)
{
	char instxt[1024] = {'\0'};

	if (ac <= 1)
	{
		printf("example usage:\n");
		printf("\t%s d503201f\n", av[0]);
		return -1;
	}

	if (!strcmp(av[1], "speed"))
	{
		srand(0xCAFE);
		for (int i = 0; i < 10000000; i++)
		{
			uint32_t insword = (rand() << 16) ^ rand();
			disassemble(0, insword, instxt);
			// printf("%08X: %s\n", 0, instxt);
		}
		return 0;
	}

	if (!strcmp(av[1], "strain") || !strcmp(av[1], "strainer") ||
	    !strcmp(av[1], "stress") || !strcmp(av[1], "stresser"))
	{
		verbose = 0;
		uint32_t insword = 0;

		while(1)
		{
			disassemble(0, insword, instxt);

			if ((insword & 0xFFFFF) == 0)
				printf("%08X: %s\n", insword, instxt);

			if(insword == 0xFFFFFFFF)
				break;

			insword += 1;
		}
		return 0;
	}

	if (!strcmp(av[1], "straindecode") || !strcmp(av[1], "strainerdecode") ||
	    !strcmp(av[1], "stressdecode") || !strcmp(av[1], "stresserdecode"))
	{
		/* decoded struct */
		Instruction instr;
		memset(&instr, 0, sizeof(instr));

		/* where to start decoding */
		uint32_t insword = 0;
		if(ac > 2)
			insword = strtoul(av[2], NULL, 16);

		/* go! */
		while(1)
		{
			aarch64_decompose(insword, &instr, 0);

			//if(1)
			if((insword & 0xFFFFF) == 0)
				printf("%08X\n", insword);

			if(insword == 0xFFFFFFFF)
				break;

			insword += 1;
		}

		return 0;
	}

	if (!strcmp(av[1], "test"))
	{
		srand(0xCAFE);
		while (1)
		{
			Instruction instr;
			memset(&instr, 0, sizeof(instr));
			uint32_t insword = (rand() << 16) ^ rand();
			aarch64_decompose(insword, &instr, 0);
			printf("%08X: %d\n", insword, instr.encoding);
		}

		return 0;
	}

	else
	{
		uint32_t insword = strtoul(av[1], NULL, 16);
		if (disassemble(0, insword, instxt) == 0)
			printf("%08X: %s\n", insword, instxt);
	}
}

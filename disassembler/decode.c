#include "decode.h"

int decode_spec(context *ctx, Instruction *dec); // from decode0.cpp
int decode_scratchpad(context *ctx, Instruction *dec); // from decode_scratchpad.c

size_t get_register_size(Register r)
{
	//Comparison done in order of likelyhood to occur
	if ((r >= REG_X0 && r <= REG_SP) || (r >= REG_D0 && r <= REG_D31))
		return 8;
	else if ((r >= REG_W0 && r <= REG_WSP) || (r >= REG_S0 && r <= REG_S31))
		return 4;
	else if (r >= REG_B0 && r <= REG_B31)
		return 1;
	else if (r >= REG_H0 && r <= REG_H31)
		return 2;
	else if ((r >= REG_Q0 && r <= REG_Q31) || (r >= REG_V0 && r <= REG_V31))
		return 16;
	else if (r >= REG_V0_B0 && r <= REG_V31_B15)
		return 1;
	else if (r >= REG_V0_H0 && r <= REG_V31_H7)
		return 2;
	else if (r >= REG_V0_S0 && r <= REG_V31_S3)
		return 4;
	else if (r >= REG_V0_D0 && r <= REG_V31_D1)
		return 8;
	return 0;
}

int aarch64_decompose(uint32_t instructionValue, Instruction *instr, uint64_t address)
{
	context ctx = { 0 };
	ctx.halted = 1; // enabled disassembly of exception instructions like DCPS1
	ctx.insword = instructionValue;
	ctx.address = address;
	ctx.features0 = 0xFFFFFFFFFFFFFFFF;
	ctx.features1 = 0xFFFFFFFFFFFFFFFF;
	ctx.EDSCR_HDE = 1;

	/* have the spec-generated code populate all the pcode variables */
	int rc = decode_spec(&ctx, instr);
	if(rc != DECODE_STATUS_OK)
		return rc;

	/* if UDF encoding, return undefined */
	if(instr->encoding == ENC_UDF_ONLY_PERM_UNDEF)
		return DECODE_STATUS_UNDEFINED;

	/* convert the pcode variables to list of operands, etc. */
	return decode_scratchpad(&ctx, instr);
}

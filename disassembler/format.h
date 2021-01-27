#pragma once

#include <stdint.h>
#include <stdbool.h>

#include "decode.h"
#include "encodings.h"
#include "operations.h"
#include "sysregs.h"

//-----------------------------------------------------------------------------
// disassembly function prototypes, return values
//-----------------------------------------------------------------------------

/* these get returned by the disassemble_instruction() function */
enum FailureCode {
	DISASM_SUCCESS=0,
	INVALID_ARGUMENTS,
	FAILED_TO_DISASSEMBLE_OPERAND,
	FAILED_TO_DISASSEMBLE_OPERATION,
	FAILED_TO_DISASSEMBLE_REGISTER,
	FAILED_TO_DECODE_INSTRUCTION,
	OUTPUT_BUFFER_TOO_SMALL,
	OPERAND_IS_NOT_REGISTER,
	NOT_MEMORY_OPERAND
};

#ifdef __cplusplus
extern "C" {
#endif
// get a text representation of the decomposed instruction
// into outBuffer
int aarch64_disassemble(Instruction *instruction, char *buf, size_t buf_sz);

int get_register_full(enum Register, const InstructionOperand *, char *result);

uint32_t get_implementation_specific(
		const InstructionOperand *operand,
		char *outBuffer,
		uint32_t outBufferSize);

/* undocumented: */
void print_instruction(Instruction *instr);

#ifdef __cplusplus
}
#endif



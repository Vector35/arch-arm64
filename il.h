#pragma once

#include "binaryninjaapi.h"
#include "disassembler/arm64dis.h"

#define IL_FLAG_N 0
#define IL_FLAG_Z 2
#define IL_FLAG_C 4
#define IL_FLAG_V 6

#define IL_FLAGWRITE_NONE       0
#define IL_FLAGWRITE_ALL        1

enum Arm64Intrinsic : uint32_t
{
	ARM64_INTRIN_ISB,
	ARM64_INTRIN_WFE,
	ARM64_INTRIN_WFI,
	ARM64_INTRIN_MSR,
	ARM64_INTRIN_MRS,
	ARM64_INTRIN_HINT_NOP,
	ARM64_INTRIN_HINT_YIELD,
	ARM64_INTRIN_HINT_WFE,
	ARM64_INTRIN_HINT_WFI,
	ARM64_INTRIN_HINT_SEV,
	ARM64_INTRIN_HINT_SEVL,
	ARM64_INTRIN_HINT_DGH,
	ARM64_INTRIN_HINT_ESB,
	ARM64_INTRIN_HINT_PSB,
	ARM64_INTRIN_HINT_TSB,
	ARM64_INTRIN_HINT_CSDB,
	ARM64_INTRIN_HINT_BTI,
	ARM64_INTRIN_SEV,
	ARM64_INTRIN_DMB,
	ARM64_INTRIN_DSB,
	ARM64_INTRIN_PRFM,
};

enum Arm64FakeRegister: uint32_t
{
	FAKEREG_NONE = arm64::SYSREG_END + 1,
	FAKEREG_SYSCALL_IMM,
	FAKEREG_END,
};

bool GetLowLevelILForInstruction(
		BinaryNinja::Architecture* arch,
		uint64_t addr,
		BinaryNinja::LowLevelILFunction& il,
		arm64::Instruction& instr,
		size_t addrSize);

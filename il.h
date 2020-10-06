#pragma once

#include "binaryninjaapi.h"
#include "disassembler/arm64dis.h"

#define IL_FLAG_N 0
#define IL_FLAG_Z 2
#define IL_FLAG_C 4
#define IL_FLAG_V 6

#define IL_FLAGWRITE_NONE       0
#define IL_FLAGWRITE_ALL        1

bool GetLowLevelILForInstruction(
		BinaryNinja::Architecture* arch,
		uint64_t addr,
		BinaryNinja::LowLevelILFunction& il,
		arm64::Instruction& instr,
		size_t addrSize);

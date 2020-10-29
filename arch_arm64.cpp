#define _CRT_SECURE_NO_WARNINGS
#define NOMINMAX

#include <inttypes.h>
#include <stdio.h>
#include <string.h>
#include <cstdint>
#include <map>

#include "binaryninjaapi.h"
#include "lowlevelilinstruction.h"
#include "il.h"
#include "arm64dis.h"

using namespace BinaryNinja;
using namespace arm64;
using namespace std;

#if defined(_MSC_VER)
#define snprintf _snprintf
#endif

enum MachoArm64RelocationType : uint32_t
{
	ARM64_RELOC_UNSIGNED            = 0,
	ARM64_RELOC_SUBTRACTOR          = 1,
	ARM64_RELOC_BRANCH26            = 2,
	ARM64_RELOC_PAGE21              = 3,
	ARM64_RELOC_PAGEOFF12           = 4,
	ARM64_RELOC_GOT_LOAD_PAGE21     = 5,
	ARM64_RELOC_GOT_LOAD_PAGEOFF12  = 6,
	ARM64_RELOC_POINTER_TO_GOT      = 7,
	ARM64_RELOC_TLVP_LOAD_PAGE21    = 8,
	ARM64_RELOC_TLVP_LOAD_PAGEOFF12 = 9,
	ARM64_RELOC_ADDEND              = 10,
	MACHO_MAX_ARM64_RELOCATION      = 11
};

enum ElfArm64RelocationType : uint32_t
{
	R_ARM_NONE                    = 0,
	R_AARCH64_NONE                = 256,
	// Data
	R_AARCH64_ABS64               = 257,
	R_AARCH64_ABS32               = 258,
	R_AARCH64_ABS16               = 259,
	R_AARCH64_PREL64              = 260,
	R_AARCH64_PREL32              = 261,
	R_AARCH64_PREL16              = 262,
	// Instructions
	R_AARCH64_MOVW_UABS_G0        = 263,
	R_AARCH64_MOVW_UABS_G0_NC     = 264,
	R_AARCH64_MOVW_UABS_G1        = 265,
	R_AARCH64_MOVW_UABS_G1_NC     = 266,
	R_AARCH64_MOVW_UABS_G2        = 267,
	R_AARCH64_MOVW_UABS_G2_NC     = 268,
	R_AARCH64_MOVW_UABS_G3        = 269,
	R_AARCH64_MOVW_SABS_G0        = 270,
	R_AARCH64_MOVW_SABS_G1        = 271,
	R_AARCH64_MOVW_SABS_G2        = 272,
	R_AARCH64_LD_PREL_LO19        = 273,
	R_AARCH64_ADR_PREL_LO21       = 274,
	R_AARCH64_ADR_PREL_PG_HI21    = 275,
	R_AARCH64_ADR_PREL_PG_HI21_NC = 276,
	R_AARCH64_ADD_ABS_LO12_NC     = 277,
	R_AARCH64_LDST8_ABS_LO12_NC   = 278,
	R_AARCH64_TSTBR14             = 279,
	R_AARCH64_CONDBR19            = 280,
	R_AARCH64_JUMP26              = 282,
	R_AARCH64_CALL26              = 283,
	R_AARCH64_LDST16_ABS_LO12_NC  = 284,
	R_AARCH64_LDST32_ABS_LO12_NC  = 285,
	R_AARCH64_LDST64_ABS_LO12_NC  = 286,
	R_AARCH64_LDST128_ABS_LO12_NC = 299,
	R_AARCH64_MOVW_PREL_G0        = 287,
	R_AARCH64_MOVW_PREL_G0_NC     = 288,
	R_AARCH64_MOVW_PREL_G1        = 289,
	R_AARCH64_MOVW_PREL_G1_NC     = 290,
	R_AARCH64_MOVW_PREL_G2        = 291,
	R_AARCH64_MOVW_PREL_G2_NC     = 292,
	R_AARCH64_MOVW_PREL_G3        = 293,
	R_AARCH64_MOVW_GOTOFF_G0      = 300,
	R_AARCH64_MOVW_GOTOFF_G0_NC   = 301,
	R_AARCH64_MOVW_GOTOFF_G1      = 302,
	R_AARCH64_MOVW_GOTOFF_G1_NC   = 303,
	R_AARCH64_MOVW_GOTOFF_G2      = 304,
	R_AARCH64_MOVW_GOTOFF_G2_NC   = 305,
	R_AARCH64_MOVW_GOTOFF_G3      = 306,
	R_AARCH64_GOTREL64            = 307,
	R_AARCH64_GOTREL32            = 308,
	R_AARCH64_GOT_LD_PREL19       = 309,
	R_AARCH64_LD64_GOTOFF_LO15    = 310,
	R_AARCH64_ADR_GOT_PAGE        = 311,
	R_AARCH64_LD64_GOT_LO12_NC    = 312,
	R_AARCH64_LD64_GOTPAGE_LO15   = 313,

	R_AARCH64_COPY                = 1024,
	R_AARCH64_GLOB_DAT            = 1025,  // Create GOT entry.
	R_AARCH64_JUMP_SLOT           = 1026,  // Create PLT entry.
	R_AARCH64_RELATIVE            = 1027,  // Adjust by program base.
	R_AARCH64_TLS_DTPREL64        = 1028,
	R_AARCH64_TLS_DTPMOD64        = 1029,
	R_AARCH64_TLS_TPREL64         = 1030,
	R_AARCH64_TLS_DTPREL32        = 1031,
	R_AARCH64_TLSDESC             = 1031,
	R_AARCH64_IRELATIVE           = 1032,
};

enum PeArm64RelocationType : uint32_t
{
	PE_IMAGE_REL_ARM64_ABSOLUTE       = 0x0000, //	The relocation is ignored.
	PE_IMAGE_REL_ARM64_ADDR32         = 0x0001, //	The 32-bit VA of the target.
	PE_IMAGE_REL_ARM64_ADDR32NB       = 0x0002, //	The 32-bit RVA of the target.
	PE_IMAGE_REL_ARM64_BRANCH26       = 0x0003, //	The 26-bit relative displacement to the target, for B and BL instructions. 
	PE_IMAGE_REL_ARM64_PAGEBASE_REL21 = 0x0004, //	The page base of the target, for ADRP instruction.
	PE_IMAGE_REL_ARM64_REL21          = 0x0005, //	The 12-bit relative displacement to the target, for instruction ADR
	PE_IMAGE_REL_ARM64_PAGEOFFSET_12A = 0x0006, //	The 12-bit page offset of the target, for instructions ADD/ADDS (immediate) with zero shift.
	PE_IMAGE_REL_ARM64_PAGEOFFSET_12L = 0x0007, //	The 12-bit page offset of the target, for instruction LDR (indexed, unsigned immediate).
	PE_IMAGE_REL_ARM64_SECREL         = 0x0008, //	The 32-bit offset of the target from the beginning of its section. This is used to support debugging information and static thread local storage.
	PE_IMAGE_REL_ARM64_SECREL_LOW12A  = 0x0009, //	Bit 0:11 of section offset of the target, for instructions ADD/ADDS (immediate) with zero shift.
	PE_IMAGE_REL_ARM64_SECREL_HIGH12A = 0x000A, //	Bit 12:23 of section offset of the target, for instructions ADD/ADDS (immediate) with zero shift.
	PE_IMAGE_REL_ARM64_SECREL_LOW12L  = 0x000B, //	Bit 0:11 of section offset of the target, for instruction LDR (indexed, unsigned immediate).
	PE_IMAGE_REL_ARM64_TOKEN          = 0x000C, //	CLR token.
	PE_IMAGE_REL_ARM64_SECTION        = 0x000D, //	The 16-bit section index of the section that contains the target. This is used to support debugging information.
	PE_IMAGE_REL_ARM64_ADDR64         = 0x000E, //	The 64-bit VA of the relocation target.
	PE_IMAGE_REL_ARM64_BRANCH19       = 0x000F, //	The 19-bit offset to the relocation target, for conditional B instruction.
	PE_IMAGE_REL_ARM64_BRANCH14       = 0x0010, //	The 14-bit offset to the relocation target, for instructions TBZ and TBNZ.
	MAX_PE_ARM64_RELOCATION           = 0x0011
};

static const char* GetRelocationString(MachoArm64RelocationType rel)
{
	static const char* relocTable[] = {
		"ARM64_RELOC_UNSIGNED",
		"ARM64_RELOC_SUBTRACTOR",
		"ARM64_RELOC_BRANCH26",
		"ARM64_RELOC_PAGE21",
		"ARM64_RELOC_PAGEOFF12",
		"ARM64_RELOC_GOT_LOAD_PAGE21",
		"ARM64_RELOC_GOT_LOAD_PAGEOFF12",
		"ARM64_RELOC_POINTER_TO_GOT",
		"ARM64_RELOC_TLVP_LOAD_PAGE21",
		"ARM64_RELOC_TLVP_LOAD_PAGEOFF12",
		"ARM64_RELOC_ADDEND"
	};
	if (rel < MACHO_MAX_ARM64_RELOCATION)
	{
		return relocTable[rel];
	}
	return "Unknown Aarch64 relocation";
}


static const char* GetRelocationString(PeArm64RelocationType rel)
{
	static const char* relocTable[] = {
		"IMAGE_REL_ARM64_ABSOLUTE",
		"IMAGE_REL_ARM64_ADDR32",
		"IMAGE_REL_ARM64_ADDR32NB",
		"IMAGE_REL_ARM64_BRANCH26",
		"IMAGE_REL_ARM64_PAGEBASE_REL21",
		"IMAGE_REL_ARM64_REL21",
		"IMAGE_REL_ARM64_PAGEOFFSET_12A",
		"IMAGE_REL_ARM64_PAGEOFFSET_12L",
		"IMAGE_REL_ARM64_SECREL",
		"IMAGE_REL_ARM64_SECREL_LOW12A",
		"IMAGE_REL_ARM64_SECREL_HIGH12A",
		"IMAGE_REL_ARM64_SECREL_LOW12L",
		"IMAGE_REL_ARM64_TOKEN",
		"IMAGE_REL_ARM64_SECTION",
		"IMAGE_REL_ARM64_ADDR64",
		"IMAGE_REL_ARM64_BRANCH19",
		"IMAGE_REL_ARM64_BRANCH14"
	};
	if (rel < MAX_PE_ARM64_RELOCATION)
	{
		return relocTable[rel];
	}
	return "Unknown Aarch64 relocation";
}


static const char* GetRelocationString(ElfArm64RelocationType rel)
{
	static map<ElfArm64RelocationType, const char*> relocMap = {
		{R_ARM_NONE,                    "R_ARM_NONE"},
		{R_AARCH64_NONE,                "R_AARCH64_NONE"},
		{R_AARCH64_ABS64,               "R_AARCH64_ABS64"},
		{R_AARCH64_ABS32,               "R_AARCH64_ABS32"},
		{R_AARCH64_ABS16,               "R_AARCH64_ABS16"},
		{R_AARCH64_PREL64,              "R_AARCH64_PREL64"},
		{R_AARCH64_PREL32,              "R_AARCH64_PREL32"},
		{R_AARCH64_PREL16,              "R_AARCH64_PREL16"},
		{R_AARCH64_MOVW_UABS_G0,        "R_AARCH64_MOVW_UABS_G0"},
		{R_AARCH64_MOVW_UABS_G0_NC,     "R_AARCH64_MOVW_UABS_G0_NC"},
		{R_AARCH64_MOVW_UABS_G1,        "R_AARCH64_MOVW_UABS_G1"},
		{R_AARCH64_MOVW_UABS_G1_NC,     "R_AARCH64_MOVW_UABS_G1_NC"},
		{R_AARCH64_MOVW_UABS_G2,        "R_AARCH64_MOVW_UABS_G2"},
		{R_AARCH64_MOVW_UABS_G2_NC,     "R_AARCH64_MOVW_UABS_G2_NC"},
		{R_AARCH64_MOVW_UABS_G3,        "R_AARCH64_MOVW_UABS_G3"},
		{R_AARCH64_MOVW_SABS_G0,        "R_AARCH64_MOVW_SABS_G0"},
		{R_AARCH64_MOVW_SABS_G1,        "R_AARCH64_MOVW_SABS_G1"},
		{R_AARCH64_MOVW_SABS_G2,        "R_AARCH64_MOVW_SABS_G2"},
		{R_AARCH64_LD_PREL_LO19,        "R_AARCH64_LD_PREL_LO19"},
		{R_AARCH64_ADR_PREL_LO21,       "R_AARCH64_ADR_PREL_LO21"},
		{R_AARCH64_ADR_PREL_PG_HI21,    "R_AARCH64_ADR_PREL_PG_HI21"},
		{R_AARCH64_ADR_PREL_PG_HI21_NC, "R_AARCH64_ADR_PREL_PG_HI21_NC"},
		{R_AARCH64_ADD_ABS_LO12_NC,     "R_AARCH64_ADD_ABS_LO12_NC"},
		{R_AARCH64_LDST8_ABS_LO12_NC,   "R_AARCH64_LDST8_ABS_LO12_NC"},
		{R_AARCH64_TSTBR14,             "R_AARCH64_TSTBR14"},
		{R_AARCH64_CONDBR19,            "R_AARCH64_CONDBR19"},
		{R_AARCH64_JUMP26,              "R_AARCH64_JUMP26"},
		{R_AARCH64_CALL26,              "R_AARCH64_CALL26"},
		{R_AARCH64_LDST16_ABS_LO12_NC,  "R_AARCH64_LDST16_ABS_LO12_NC"},
		{R_AARCH64_LDST32_ABS_LO12_NC,  "R_AARCH64_LDST32_ABS_LO12_NC"},
		{R_AARCH64_LDST64_ABS_LO12_NC,  "R_AARCH64_LDST64_ABS_LO12_NC"},
		{R_AARCH64_LDST128_ABS_LO12_NC, "R_AARCH64_LDST128_ABS_LO12_NC"},
		{R_AARCH64_MOVW_PREL_G0,        "R_AARCH64_MOVW_PREL_G0"},
		{R_AARCH64_MOVW_PREL_G0_NC,     "R_AARCH64_MOVW_PREL_G0_NC"},
		{R_AARCH64_MOVW_PREL_G1,        "R_AARCH64_MOVW_PREL_G1"},
		{R_AARCH64_MOVW_PREL_G1_NC,     "R_AARCH64_MOVW_PREL_G1_NC"},
		{R_AARCH64_MOVW_PREL_G2,        "R_AARCH64_MOVW_PREL_G2"},
		{R_AARCH64_MOVW_PREL_G2_NC,     "R_AARCH64_MOVW_PREL_G2_NC"},
		{R_AARCH64_MOVW_PREL_G3,        "R_AARCH64_MOVW_PREL_G3"},
		{R_AARCH64_MOVW_GOTOFF_G0,      "R_AARCH64_MOVW_GOTOFF_G0"},
		{R_AARCH64_MOVW_GOTOFF_G0_NC,   "R_AARCH64_MOVW_GOTOFF_G0_NC"},
		{R_AARCH64_MOVW_GOTOFF_G1,      "R_AARCH64_MOVW_GOTOFF_G1"},
		{R_AARCH64_MOVW_GOTOFF_G1_NC,   "R_AARCH64_MOVW_GOTOFF_G1_NC"},
		{R_AARCH64_MOVW_GOTOFF_G2,      "R_AARCH64_MOVW_GOTOFF_G2"},
		{R_AARCH64_MOVW_GOTOFF_G2_NC,   "R_AARCH64_MOVW_GOTOFF_G2_NC"},
		{R_AARCH64_MOVW_GOTOFF_G3,      "R_AARCH64_MOVW_GOTOFF_G3"},
		{R_AARCH64_GOTREL64,            "R_AARCH64_GOTREL64"},
		{R_AARCH64_GOTREL32,            "R_AARCH64_GOTREL32"},
		{R_AARCH64_GOT_LD_PREL19,       "R_AARCH64_GOT_LD_PREL19"},
		{R_AARCH64_LD64_GOTOFF_LO15,    "R_AARCH64_LD64_GOTOFF_LO15"},
		{R_AARCH64_ADR_GOT_PAGE,        "R_AARCH64_ADR_GOT_PAGE"},
		{R_AARCH64_LD64_GOT_LO12_NC,    "R_AARCH64_LD64_GOT_LO12_NC"},
		{R_AARCH64_LD64_GOTPAGE_LO15,   "R_AARCH64_LD64_GOTPAGE_LO15"},
		{R_AARCH64_COPY,                "R_AARCH64_COPY"},
		{R_AARCH64_GLOB_DAT,            "R_AARCH64_GLOB_DAT"},
		{R_AARCH64_JUMP_SLOT,           "R_AARCH64_JUMP_SLOT"},
		{R_AARCH64_RELATIVE,            "R_AARCH64_RELATIVE"},
		{R_AARCH64_TLS_DTPREL64,        "R_AARCH64_TLS_DTPREL64"},
		{R_AARCH64_TLS_DTPMOD64,        "R_AARCH64_TLS_DTPMOD64"},
		{R_AARCH64_TLS_TPREL64,         "R_AARCH64_TLS_TPREL64"},
		{R_AARCH64_TLS_DTPREL32,        "R_AARCH64_TLS_DTPREL32"},
		{R_AARCH64_IRELATIVE,           "R_AARCH64_IRELATIVE"}
	};

	if (relocMap.count(rel))
		return relocMap.at(rel);
	return "Unknown Aarch64 relocation";
}


class Arm64Architecture: public Architecture
{
protected:
	size_t m_bits;

	virtual bool Disassemble(const uint8_t* data, uint64_t addr, size_t maxLen, Instruction& result)
	{
		(void)addr;
		(void)maxLen;
		memset(&result, 0, sizeof(result));
		if (aarch64_decompose(*(uint32_t*)data, &result, addr) != 0)
			return false;
		return true;
	}


	virtual size_t GetAddressSize() const override
	{
		return 8;
	}


	virtual size_t GetInstructionAlignment() const override
	{
		return 4;
	}


	virtual size_t GetMaxInstructionLength() const override
	{
		return 4;
	}


	bool IsTestAndBranch(const Instruction& instr)
	{
		return instr.operation == ARM64_TBZ || instr.operation == ARM64_TBNZ;
	}


	bool IsCompareAndBranch(const Instruction& instr)
	{
		return instr.operation == ARM64_CBZ || instr.operation == ARM64_CBNZ;
	}


	bool IsConditionalBranch(const Instruction& instr)
	{
		switch (instr.operation)
		{
		case ARM64_B_EQ:
		case ARM64_B_NE:
		case ARM64_B_CS:
		case ARM64_B_CC:
		case ARM64_B_MI:
		case ARM64_B_PL:
		case ARM64_B_VS:
		case ARM64_B_VC:
		case ARM64_B_HI:
		case ARM64_B_LS:
		case ARM64_B_GE:
		case ARM64_B_LT:
		case ARM64_B_GT:
		case ARM64_B_LE:
		case ARM64_B_AL:
		case ARM64_B_NV:
			return true;
		default:
			return false;
		}
	}


	bool IsConditionalJump(const Instruction& instr)
	{
		return IsConditionalBranch(instr) || IsTestAndBranch(instr) || IsCompareAndBranch(instr);
	}


	void SetInstructionInfoForInstruction(uint64_t addr, const Instruction& instr, InstructionInfo& result)
	{
		result.length = 4;
		switch (instr.operation)
		{
		case ARM64_BL:
			if (instr.operands[0].operandClass == LABEL)
				result.AddBranch(CallDestination, instr.operands[0].immediate);
			break;

		case ARM64_B:
			if (instr.operands[0].operandClass == LABEL)
				result.AddBranch(UnconditionalBranch, instr.operands[0].immediate);
			else
				result.AddBranch(UnresolvedBranch);
			break;

		case ARM64_B_EQ:
		case ARM64_B_NE:
		case ARM64_B_CS:
		case ARM64_B_CC:
		case ARM64_B_MI:
		case ARM64_B_PL:
		case ARM64_B_VS:
		case ARM64_B_VC:
		case ARM64_B_HI:
		case ARM64_B_LS:
		case ARM64_B_GE:
		case ARM64_B_LT:
		case ARM64_B_GT:
		case ARM64_B_LE:
		case ARM64_B_AL:
		case ARM64_B_NV:
			result.AddBranch(TrueBranch, instr.operands[0].immediate);
			result.AddBranch(FalseBranch, addr + 4);
			break;
		case ARM64_TBZ:
		case ARM64_TBNZ:
			result.AddBranch(TrueBranch, instr.operands[2].immediate);
			result.AddBranch(FalseBranch, addr + 4);
			break;
		case ARM64_CBZ:
		case ARM64_CBNZ:
			result.AddBranch(TrueBranch, instr.operands[1].immediate);
			result.AddBranch(FalseBranch, addr + 4);
			break;
		case ARM64_ERET:
		case ARM64_DRPS:
		case ARM64_BR:
		case ARM64_BRAA:
		case ARM64_BRAAZ:
		case ARM64_BRAB:
		case ARM64_BRABZ:
			result.AddBranch(UnresolvedBranch);
			break;
		case ARM64_RET:
		case ARM64_RETAA:
		case ARM64_RETAB:
			result.AddBranch(FunctionReturn);
			break;

		case ARM64_SVC:
			if (instr.operands[0].immediate == 0)
				result.AddBranch(SystemCall);
			break;

		default:
			break;
		}
	}


	uint32_t tokenize_shift(const InstructionOperand* __restrict instructionOperand, vector<InstructionTextToken>& result)
	{
		char operand[64] = {0};
		if (instructionOperand->shiftType != SHIFT_NONE)
		{
			const char* shiftStr = get_shift(instructionOperand->shiftType);
			if (shiftStr == NULL)
				return FAILED_TO_DISASSEMBLE_OPERAND;

			result.emplace_back(TextToken, ", ");
			result.emplace_back(TextToken, shiftStr);
			if (instructionOperand->shiftValueUsed != 0)
			{
				snprintf(operand, sizeof(operand), "%#x", (uint32_t)instructionOperand->shiftValue);
				result.emplace_back(TextToken, " #");
				result.emplace_back(IntegerToken, operand, instructionOperand->shiftValue);
			}
		}
		return DISASM_SUCCESS;
	}


	uint32_t tokenize_shifted_immediate(const InstructionOperand* __restrict instructionOperand,	vector<InstructionTextToken>& result)
	{
		char operand[64] = {0};
		const char* sign = "";
		if (instructionOperand == NULL)
			return FAILED_TO_DISASSEMBLE_OPERAND;

		uint64_t imm = instructionOperand->immediate;
		if (instructionOperand->signedImm == 1 && ((int64_t)imm) < 0)
		{
			sign = "-";
			imm = -(int64_t)imm;
		}

		switch (instructionOperand->operandClass)
		{
		case FIMM32:
			{
			union
			{
				uint32_t intValue;
				float floatValue;
			} f;
			f.intValue = (uint32_t)instructionOperand->immediate;
			snprintf(operand, sizeof(operand), "%f", f.floatValue);
			result.emplace_back(TextToken, "#");
			result.emplace_back(FloatingPointToken, operand);
			break;
			}
		case IMM32:
			snprintf(operand, sizeof(operand), "%s%#x", sign, (uint32_t)imm);
			result.emplace_back(TextToken, "#");
			result.emplace_back(IntegerToken, operand, instructionOperand->immediate);
			break;
		case IMM64:
			snprintf(operand, sizeof(operand), "%s%#" PRIx64 , sign, imm);
			result.emplace_back(TextToken, "#");
			result.emplace_back(IntegerToken, operand, instructionOperand->immediate);
			break;
		case LABEL:
			snprintf(operand, sizeof(operand), "%#" PRIx64 , instructionOperand->immediate);
			result.emplace_back(PossibleAddressToken, operand, instructionOperand->immediate);
			break;
		default:
			return FAILED_TO_DISASSEMBLE_OPERAND;
		}

		tokenize_shift(instructionOperand, result);
		return DISASM_SUCCESS;
	}


	uint32_t tokenize_shifted_register(
		const InstructionOperand* restrict instructionOperand,
		uint32_t registerNumber,
		vector<InstructionTextToken>& result)
	{
		const char* reg = get_register_name((enum Register)instructionOperand->reg[registerNumber]);
		if (reg == NULL)
			return FAILED_TO_DISASSEMBLE_REGISTER;

		result.emplace_back(RegisterToken, reg);
		tokenize_shift(instructionOperand, result);
		return DISASM_SUCCESS;
	}


	uint32_t tokenize_register(
			const InstructionOperand* restrict instructionOperand,
			uint32_t registerNumber,
			vector<InstructionTextToken>& result)
	{
		char operand[32] = {0};
		if (instructionOperand->operandClass == SYS_REG)
		{
			snprintf(operand, sizeof(operand), "%s",
			get_system_register_name((SystemReg)instructionOperand->reg[registerNumber]));

			result.emplace_back(RegisterToken, operand);
			return DISASM_SUCCESS;
		}
		else if (instructionOperand->operandClass != REG && instructionOperand->operandClass != MULTI_REG)
			return OPERAND_IS_NOT_REGISTER;

		if (instructionOperand->shiftType != SHIFT_NONE)
		{
			return tokenize_shifted_register(instructionOperand, registerNumber, result);
		}
		else if (instructionOperand->elementSize == 0)
		{
			enum Register r = (enum Register)(instructionOperand->reg[registerNumber]);
			snprintf(operand, sizeof(operand), "%s", get_register_name(r));
			result.emplace_back(RegisterToken, operand);
			return DISASM_SUCCESS;
		}
		char elementSize;
		switch (instructionOperand->elementSize)
		{
			case 1: elementSize = 'b'; break;
			case 2: elementSize = 'h'; break;
			case 4: elementSize = 's'; break;
			case 8: elementSize = 'd'; break;
			case 16: elementSize = 'q'; break;
			default:
				return FAILED_TO_DISASSEMBLE_REGISTER;
		}

		if (instructionOperand->dataSize != 0)
		{
			if (registerNumber > 3 ||
				(instructionOperand->dataSize != 1 &&
				instructionOperand->dataSize != 2 &&
				instructionOperand->dataSize != 4 &&
				instructionOperand->dataSize != 8 &&
				instructionOperand->dataSize != 16))
			{
				return FAILED_TO_DISASSEMBLE_REGISTER;
			}
			snprintf(operand, sizeof(operand), "%s", get_register_name((enum Register)instructionOperand->reg[registerNumber]));
			result.emplace_back(RegisterToken, operand);
			snprintf(operand, sizeof(operand), ".%u%c", instructionOperand->dataSize, elementSize);
			result.emplace_back(TextToken, operand);
		}
		else
		{
			if (registerNumber > 3)
				return FAILED_TO_DISASSEMBLE_REGISTER;

			snprintf(operand, sizeof(operand), "%s", get_register_name((enum Register)instructionOperand->reg[registerNumber]));
			result.emplace_back(RegisterToken, operand);
			snprintf(operand,sizeof(operand), ".%c", elementSize);
			result.emplace_back(TextToken, operand);
		}
		return DISASM_SUCCESS;
	}


	uint32_t tokenize_memory_operand(
		const InstructionOperand* restrict instructionOperand,
		vector<InstructionTextToken>& result)
	{
		char immBuff[32] = {0};
		char paramBuff[32] = {0};
		const char* reg1 = get_register_name((enum Register)instructionOperand->reg[0]);
		const char* reg2 = get_register_name((enum Register)instructionOperand->reg[1]);

		const char* sign = "";
		int64_t imm = instructionOperand->immediate;
		if (instructionOperand->signedImm && (int64_t)imm < 0)
		{
			sign = "-";
			imm = -imm;
		}
		const char* startToken = "[";
		const char* endToken =	 "]";
		result.emplace_back(BeginMemoryOperandToken, startToken);
		result.emplace_back(RegisterToken, reg1);
		switch (instructionOperand->operandClass)
		{
		case MEM_REG: break;
		case MEM_PRE_IDX:
			endToken = "]!";
			snprintf(immBuff, sizeof(immBuff), "%s%#" PRIx64, sign, (uint64_t)imm);
			result.emplace_back(TextToken, ", #");
			result.emplace_back(IntegerToken, immBuff, instructionOperand->immediate);
			break;
		case MEM_POST_IDX: // [<reg>], <reg|imm>
			endToken = NULL;
			if (reg2 != NULL)
			{
				result.emplace_back(EndMemoryOperandToken, "], ");
				result.emplace_back(RegisterToken, reg2);
			}
			else
			{
				snprintf(paramBuff, sizeof(paramBuff), "%s%#" PRIx64, sign, (uint64_t)imm);
				result.emplace_back(EndMemoryOperandToken, "], #");
				result.emplace_back(IntegerToken, paramBuff, instructionOperand->immediate);
			}
			break;
		case MEM_OFFSET: // [<reg> optional(imm)]
			if (instructionOperand->immediate != 0)
			{
				snprintf(immBuff, sizeof(immBuff), "%s%#" PRIx64, sign, (uint64_t)imm);
				result.emplace_back(TextToken, ", #");
				result.emplace_back(IntegerToken, immBuff, instructionOperand->immediate);
			}
			break;
		case MEM_EXTENDED: // [<reg>, <reg> optional(shift optional(imm))]
			if (reg2 == NULL)
				return FAILED_TO_DISASSEMBLE_OPERAND;

			result.emplace_back(TextToken, ", ");
			result.emplace_back(RegisterToken, reg2);
			tokenize_shift(instructionOperand, result);
			break;
		default:
			return NOT_MEMORY_OPERAND;
		}
		if (endToken != NULL)
			result.emplace_back(EndMemoryOperandToken, endToken);
		return DISASM_SUCCESS;
	}


	uint32_t tokenize_multireg_operand(const InstructionOperand* restrict operand,
		vector<InstructionTextToken>& result)
	{
		char index[32] = {0};
		uint32_t elementCount = 0;

		result.emplace_back(TextToken, "{");
		for (; elementCount < 4 && operand->reg[elementCount] != REG_NONE; elementCount++)
		{
			if (elementCount != 0)
				result.emplace_back(TextToken, ", ");

			if (tokenize_register(operand, elementCount, result) != 0)
				return FAILED_TO_DISASSEMBLE_OPERAND;
		}
		result.emplace_back(TextToken, "}");

		if(operand->index != 0)
		{
			result.emplace_back(TextToken, "[");
			snprintf(index, sizeof(index), "%d", operand->index);
			result.emplace_back(IntegerToken, index, operand->index);
			result.emplace_back(TextToken, "]");
		}
		return DISASM_SUCCESS;
	}


	uint32_t tokenize_condition(const InstructionOperand* restrict instructionOperand,
		vector<InstructionTextToken>& result)
	{
		const char* condStr = get_condition((Condition)instructionOperand->reg[0]);
		if (condStr == NULL)
			return FAILED_TO_DISASSEMBLE_OPERAND;

		result.emplace_back(TextToken, condStr);
		return DISASM_SUCCESS;
	}


	uint32_t tokenize_implementation_specific(const InstructionOperand* restrict instructionOperand,
		vector<InstructionTextToken>& result)
	{
		char operand[32] = {0};
		get_implementation_specific(instructionOperand, operand, sizeof(operand));
		result.emplace_back(RegisterToken, operand);
		return DISASM_SUCCESS;
	}


	BNRegisterInfo RegisterInfo(uint32_t fullWidthReg, size_t offset, size_t size, bool zeroExtend = false)
	{
		BNRegisterInfo result;
		result.fullWidthRegister = fullWidthReg;
		result.offset = offset;
		result.size = size;
		result.extend = zeroExtend ? ZeroExtendToFullWidth : NoExtend;
		return result;
	}


public:
	Arm64Architecture(): Architecture("aarch64"), m_bits(64)
	{
	}

	bool CanAssemble() override
	{
		return true;
	}

	bool Assemble(const string& code, uint64_t addr, DataBuffer& result, string& errors) override
	{
		(void)addr;

		int assembleResult;
		char *instrBytes=NULL, *err=NULL;
		int instrBytesLen=0, errLen=0;

		BNLlvmServicesInit();

		errors.clear();
		assembleResult = BNLlvmServicesAssemble(code.c_str(), LLVM_SVCS_DIALECT_UNSPEC,
		  "aarch64-none-none", LLVM_SVCS_CM_DEFAULT, LLVM_SVCS_RM_STATIC,
		  &instrBytes, &instrBytesLen, &err, &errLen);

		if(assembleResult || errLen) {
			errors = err;
			BNLlvmServicesAssembleFree(instrBytes, err);
			return false;
		}

		result.Clear();
		result.Append(instrBytes, instrBytesLen);
		BNLlvmServicesAssembleFree(instrBytes, err);
		return true;
	}

	virtual BNEndianness GetEndianness() const override
	{
		return LittleEndian;
	}


	virtual bool GetInstructionInfo(const uint8_t* data, uint64_t addr, size_t maxLen, InstructionInfo& result) override
	{
		if (maxLen < 4)
			return false;

		Instruction instr;
		if (!Disassemble(data, addr, maxLen, instr))
			return false;

		SetInstructionInfoForInstruction(addr, instr, result);
		return true;
	}


	virtual bool GetInstructionText(const uint8_t* data, uint64_t addr, size_t& len, vector<InstructionTextToken>& result) override
	{
		len = 4;
		Instruction instr;
		bool tokenizeSuccess = false;
		char padding[9];
		if (!Disassemble(data, addr, len, instr))
			return false;

		memset(padding, 0x20, sizeof(padding));
		const char* operation = get_operation(&instr);
		if (operation == nullptr)
			return false;

		size_t operationLen = strlen(operation);
		if (operationLen < 8)
		{
			padding[8-operationLen] = '\0';
		}
		else
			padding[1] = '\0';

		result.emplace_back(InstructionToken, operation);
		result.emplace_back(TextToken, padding);
		for (size_t i = 0; i < MAX_OPERANDS; i++)
		{
			if (instr.operands[i].operandClass == NONE)
				return true;

			if (i != 0)
				result.emplace_back(OperandSeparatorToken, ", ");

			switch (instr.operands[i].operandClass)
			{
			case FIMM32:
			case IMM32:
			case IMM64:
			case LABEL:
				tokenizeSuccess = tokenize_shifted_immediate(&instr.operands[i], result) == 0;
				break;
			case MEM_REG:
			case MEM_PRE_IDX:
			case MEM_POST_IDX:
			case MEM_OFFSET:
			case MEM_EXTENDED:
				tokenizeSuccess = tokenize_memory_operand(&instr.operands[i], result) == 0;
				break;
			case REG:
			case SYS_REG:
				tokenizeSuccess = tokenize_register(&instr.operands[i], 0, result) == 0;
				break;
			case MULTI_REG:
				tokenizeSuccess = tokenize_multireg_operand(&instr.operands[i], result) == 0;
				break;
			case CONDITION:
				tokenizeSuccess = tokenize_condition(&instr.operands[i], result) == 0;
				break;
			case IMPLEMENTATION_SPECIFIC:
				tokenizeSuccess = tokenize_implementation_specific(&instr.operands[i], result) == 0;
				break;
			default:
				LogError("operandClass %x\n", instr.operands[i].operandClass);
				return false;
			}
			if (!tokenizeSuccess)
			{
				LogError("tokenize failed operandClass %x\n", instr.operands[i].operandClass);
				return false;
			}
		}
		return true;
	}


	virtual string GetIntrinsicName(uint32_t intrinsic) override
	{
		switch (intrinsic)
		{
		case ARM64_INTRIN_ISB:
			return "__isb";
		case ARM64_INTRIN_WFE:
			return "__wfe";
		case ARM64_INTRIN_WFI:
			return "__wfi";
		case ARM64_INTRIN_MSR:
			return "_WriteStatusReg";
		case ARM64_INTRIN_MRS:
			return "_ReadStatusReg";
		case ARM64_INTRIN_HINT_DGH:
			return "SystemHintOp_DGH";
		case ARM64_INTRIN_ESB:
			return "SystemHintOp_ESB";
		case ARM64_INTRIN_PACDA:
			return "__pacda";
		case ARM64_INTRIN_PACDB:
			return "__pacdb";
		case ARM64_INTRIN_PACDZA:
			return "__pacdza";
		case ARM64_INTRIN_PACDZB:
			return "__pacdzb";
		case ARM64_INTRIN_PACIA:
			return "__pacia";
		case ARM64_INTRIN_PACIA1716:
			return "__pacia1716";
		case ARM64_INTRIN_PACIASP:
			return "__paciasp";
		case ARM64_INTRIN_PACIAZ:
			return "__paciaz";
		case ARM64_INTRIN_PACIZA:
			return "__paciza";
		case ARM64_INTRIN_PACIB:
			return "__pacib";
		case ARM64_INTRIN_PACIB1716:
			return "__pacib1716";
		case ARM64_INTRIN_PACIBSP:
			return "__pacibsp";
		case ARM64_INTRIN_PACIBZ:
			return "__pacibz";
		case ARM64_INTRIN_PACIZB:
			return "__pacizb";
		case ARM64_INTRIN_PSBCSYNC:
			return "SystemHintOp_PSB";
		case ARM64_INTRIN_HINT_TSB:
			return "SystemHintOp_TSB";
		case ARM64_INTRIN_HINT_CSDB:
			return "SystemHintOp_CSDB";
		case ARM64_INTRIN_HINT_BTI:
			return "SystemHintOp_BTI";
		case ARM64_INTRIN_SEV:
			return "__sev";
		case ARM64_INTRIN_SEVL:
			return "__sevl";
		case ARM64_INTRIN_DMB:
			return "__dmb";
		case ARM64_INTRIN_DSB:
			return "__dsb";
		case ARM64_INTRIN_YIELD:
			return "__yield";
		case ARM64_INTRIN_PRFM:
			return "__prefetch";
		default:
			return "";
		}
	}


	virtual vector<uint32_t> GetAllIntrinsics() override
	{
		return vector<uint32_t> {
			ARM64_INTRIN_DMB, ARM64_INTRIN_DSB, ARM64_INTRIN_ESB, ARM64_INTRIN_HINT_BTI, ARM64_INTRIN_HINT_CSDB,
			ARM64_INTRIN_HINT_DGH, ARM64_INTRIN_HINT_TSB, ARM64_INTRIN_ISB, ARM64_INTRIN_MRS, ARM64_INTRIN_MSR,
			ARM64_INTRIN_PACDA, ARM64_INTRIN_PACDB, ARM64_INTRIN_PACDZA, ARM64_INTRIN_PACDZB,
			ARM64_INTRIN_PACIA, ARM64_INTRIN_PACIA1716, ARM64_INTRIN_PACIASP,
			ARM64_INTRIN_PACIAZ, ARM64_INTRIN_PACIZA,
			ARM64_INTRIN_PACIB, ARM64_INTRIN_PACIB1716, ARM64_INTRIN_PACIBSP,
			ARM64_INTRIN_PACIBZ, ARM64_INTRIN_PACIZB,
			ARM64_INTRIN_PRFM, ARM64_INTRIN_PSBCSYNC, ARM64_INTRIN_SEV, ARM64_INTRIN_SEVL, ARM64_INTRIN_WFE,
			ARM64_INTRIN_WFI, ARM64_INTRIN_YIELD
		};
	}


	virtual vector<NameAndType> GetIntrinsicInputs(uint32_t intrinsic) override
	{
		switch (intrinsic)
		{
		case ARM64_INTRIN_MSR:
			return {NameAndType(Type::IntegerType(8, false))};
		case ARM64_INTRIN_MRS:
			return {NameAndType(Type::IntegerType(4, false))};
		case ARM64_INTRIN_PACDA: // reads <Xn>
		case ARM64_INTRIN_PACDB: // reads <Xn>
		case ARM64_INTRIN_PACIA: // reads <Xn>
		case ARM64_INTRIN_PACIB: // reads <Xn>
		case ARM64_INTRIN_PACIA1716: // reads x16
		case ARM64_INTRIN_PACIB1716: // reads x16
		case ARM64_INTRIN_PRFM:
			return {NameAndType(Type::IntegerType(8, false))};
		case ARM64_INTRIN_PACIASP: // reads x30, sp
		case ARM64_INTRIN_PACIBSP: // reads x30, sp
			return {NameAndType(Type::IntegerType(8, false)), NameAndType(Type::IntegerType(8, false))};
		case ARM64_INTRIN_DMB:
		case ARM64_INTRIN_DSB:
		case ARM64_INTRIN_ESB:
		case ARM64_INTRIN_HINT_BTI:
		case ARM64_INTRIN_HINT_CSDB:
		case ARM64_INTRIN_HINT_DGH:
		case ARM64_INTRIN_HINT_TSB:
		case ARM64_INTRIN_ISB:
		case ARM64_INTRIN_PACDZA: // modifier is 0
		case ARM64_INTRIN_PACDZB: // modifier is 0
		case ARM64_INTRIN_PACIAZ: // modifier is 0
		case ARM64_INTRIN_PACIBZ: // modifier is 0
		case ARM64_INTRIN_PACIZA: // modifier is 0
		case ARM64_INTRIN_PACIZB: // modifier is 0
		case ARM64_INTRIN_PSBCSYNC:
		case ARM64_INTRIN_SEV:
		case ARM64_INTRIN_SEVL:
		case ARM64_INTRIN_WFE:
		case ARM64_INTRIN_WFI:
		case ARM64_INTRIN_YIELD:
		default:
			return vector<NameAndType>();
		}
	}


	virtual vector<Confidence<Ref<Type>>> GetIntrinsicOutputs(uint32_t intrinsic) override
	{
		switch (intrinsic)
		{
		case ARM64_INTRIN_MSR:
			return {Type::IntegerType(4, false)};
		case ARM64_INTRIN_MRS:
		case ARM64_INTRIN_PACDA: // writes <Xd>
		case ARM64_INTRIN_PACDB: // writes <Xd>
		case ARM64_INTRIN_PACDZA: // writes <Xd>
		case ARM64_INTRIN_PACDZB: // writes <Xd>
		case ARM64_INTRIN_PACIA1716: // writes x17
		case ARM64_INTRIN_PACIA: // writes <Xd>
		case ARM64_INTRIN_PACIASP: // writes x30
		case ARM64_INTRIN_PACIAZ: // writes x30
		case ARM64_INTRIN_PACIB1716: // writes x17
		case ARM64_INTRIN_PACIB: // writes <Xd>
		case ARM64_INTRIN_PACIBSP: // writes x30
		case ARM64_INTRIN_PACIBZ: // writes x30
		case ARM64_INTRIN_PACIZA: // writes <Xd>
		case ARM64_INTRIN_PACIZB: // writes <Xd>
			return {Type::IntegerType(8, false)};
		case ARM64_INTRIN_ISB:
		case ARM64_INTRIN_WFE:
		case ARM64_INTRIN_WFI:
		case ARM64_INTRIN_HINT_DGH:
		case ARM64_INTRIN_ESB:
		case ARM64_INTRIN_PSBCSYNC:
		case ARM64_INTRIN_HINT_TSB:
		case ARM64_INTRIN_HINT_CSDB:
		case ARM64_INTRIN_HINT_BTI:
		case ARM64_INTRIN_SEV:
		case ARM64_INTRIN_SEVL:
		case ARM64_INTRIN_DMB:
		case ARM64_INTRIN_DSB:
		case ARM64_INTRIN_YIELD:
		case ARM64_INTRIN_PRFM:
		default:
			return vector<Confidence<Ref<Type>>>();
		}
	}


	virtual bool IsNeverBranchPatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override
	{
		Instruction instr;
		if (!Disassemble(data, addr, len, instr))
			return false;
		return IsConditionalBranch(instr);
	}


	virtual bool IsAlwaysBranchPatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override
	{
		Instruction instr;
		if (!Disassemble(data, addr, len, instr))
			return false;
		return IsConditionalBranch(instr);
	}


	virtual bool IsInvertBranchPatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override
	{
		Instruction instr;
		if (!Disassemble(data, addr, len, instr))
			return false;
		return IsConditionalJump(instr);
	}


	virtual bool IsSkipAndReturnZeroPatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override
	{
		Instruction instr;
		if (!Disassemble(data, addr, len, instr))
			return false;
		return instr.operation == ARM64_BL || instr.operation == ARM64_BR || instr.operation == ARM64_BLR;
	}


	virtual bool IsSkipAndReturnValuePatchAvailable(const uint8_t* data, uint64_t addr, size_t len) override
	{
		Instruction instr;
		if (!Disassemble(data, addr, len, instr))
			return false;
		return instr.operation == ARM64_BL || instr.operation == ARM64_BR || instr.operation == ARM64_BLR;
	}


	virtual bool ConvertToNop(uint8_t* data, uint64_t, size_t len) override
	{
		uint32_t arm64_nop =	0xd503201f;
		if (len < sizeof(arm64_nop))
			return false;
		for (size_t i = 0; i < len/sizeof(arm64_nop); i++)
			((uint32_t*)data)[i] = arm64_nop;
		return true;
	}


	virtual bool AlwaysBranch(uint8_t* data, uint64_t addr, size_t len) override
	{
		Instruction instr;
		if (!Disassemble(data, addr, len, instr))
			return false;

		uint32_t *value = (uint32_t*)data;
		//Combine the immediate in the first operand with the unconditional branch opcode to form
		//an unconditional branch instruction
		*value = (5 << 26) | (uint32_t)((instr.operands[0].immediate - addr) >> 2);
		return true;
	}


	virtual bool InvertBranch(uint8_t* data, uint64_t addr, size_t len) override
	{
		Instruction instr;
		if (!Disassemble(data, addr, len, instr))
			return false;

		uint32_t *value = (uint32_t*)data;
		if (IsConditionalBranch(instr))
		{
			//The inverted branch is the inversion of the low order nibble
			*value ^= 1;
		}
		else if (IsTestAndBranch(instr) || IsCompareAndBranch(instr))
		{
			//invert bit 24
			*value ^= (1 << 24);
		}
		return true;
	}


	virtual bool SkipAndReturnValue(uint8_t* data, uint64_t addr, size_t len, uint64_t value) override
	{
		(void)addr;
		//Return value is put in X0. The largest value that we can put into a single integer is 16 bits
		if (value > 0xffff || len > 4)
			return false;

		uint32_t movValueR0 = 0xd2800000;
		uint32_t *inst = (uint32_t*)data;
		*inst = movValueR0 | ((uint32_t)value << 5);
		return true;
	}


	virtual bool GetInstructionLowLevelIL(const uint8_t* data, uint64_t addr, size_t& len, LowLevelILFunction& il) override
	{
		Instruction instr;
		if (!Disassemble(data, addr, len, instr))
		{
			il.AddInstruction(il.Undefined());
			return false;
		}

		len = 4;
		return GetLowLevelILForInstruction(this, addr, il, instr, GetAddressSize());
	}


	virtual string GetFlagName(uint32_t flag) override
	{
		char result[32];
		switch (flag)
		{
		case IL_FLAG_N:
			return "n";
		case IL_FLAG_Z:
			return "z";
		case IL_FLAG_C:
			return "c";
		case IL_FLAG_V:
			return "v";
		default:
			sprintf(result, "flag%" PRIu32, flag);
			return result;
		}
	}


	virtual string GetFlagWriteTypeName(uint32_t flags) override
	{
		switch (flags)
		{
		case IL_FLAGWRITE_ALL:
			return "*";
		default:
			return "";
		}
	}


	virtual BNFlagRole GetFlagRole(uint32_t flag, uint32_t) override
	{
		switch (flag)
		{
		case IL_FLAG_N:
			return NegativeSignFlagRole;
		case IL_FLAG_Z:
			return ZeroFlagRole;
		case IL_FLAG_C:
			return CarryFlagRole;
		case IL_FLAG_V:
			return OverflowFlagRole;
		default:
			return SpecialFlagRole;
		}
	}


	virtual vector<uint32_t> GetFlagsWrittenByFlagWriteType(uint32_t flags) override
	{
		switch (flags)
		{
		case IL_FLAGWRITE_ALL:
			return vector<uint32_t> { IL_FLAG_N, IL_FLAG_Z, IL_FLAG_C, IL_FLAG_V };
		default:
			return vector<uint32_t> {};
		}
	}


	virtual vector<uint32_t> GetFlagsRequiredForFlagCondition(BNLowLevelILFlagCondition cond, uint32_t) override
	{
		switch (cond)
		{
		case LLFC_E:
		case LLFC_NE:
			return vector<uint32_t>{ IL_FLAG_Z };
		case LLFC_SLT:
		case LLFC_SGE:
			return vector<uint32_t>{ IL_FLAG_N, IL_FLAG_V };
		case LLFC_ULT:
		case LLFC_UGE:
			return vector<uint32_t>{ IL_FLAG_C };
		case LLFC_SLE:
		case LLFC_SGT:
			return vector<uint32_t>{ IL_FLAG_Z, IL_FLAG_N, IL_FLAG_V };
		case LLFC_ULE:
		case LLFC_UGT:
			return vector<uint32_t>{ IL_FLAG_C, IL_FLAG_Z };
		case LLFC_NEG:
		case LLFC_POS:
			return vector<uint32_t>{ IL_FLAG_N };
		case LLFC_O:
		case LLFC_NO:
			return vector<uint32_t>{ IL_FLAG_V };
		default:
			return vector<uint32_t>();
		}
	}


	virtual string GetRegisterName(uint32_t reg) override
	{
		switch (reg) {
		case REG_NONE:
			return "";
		case FAKEREG_SYSCALL_IMM:
			return "syscall_imm";
		}

		const char* regName = get_register_name((enum Register)reg);

		if (!regName)
			return "";

		return regName;
	}


	virtual vector<uint32_t> GetFullWidthRegisters() override
	{
		return vector<uint32_t>{
			REG_X0,   REG_X1,  REG_X2,  REG_X3,   REG_X4,  REG_X5,  REG_X6,  REG_X7,
			REG_X8,   REG_X9,  REG_X10, REG_X11,  REG_X12, REG_X13, REG_X14, REG_X15,
			REG_X16,  REG_X17, REG_X18, REG_X19,  REG_X20, REG_X21, REG_X22, REG_X23,
			REG_X24,  REG_X25, REG_X26, REG_X27,  REG_X28, REG_X29, REG_X30, REG_SP,  REG_XZR,
			REG_Q0,   REG_Q1,  REG_Q2,  REG_Q3,   REG_Q4,  REG_Q5,  REG_Q6,  REG_Q7,
			REG_Q8,   REG_Q9,  REG_Q10, REG_Q11,  REG_Q12, REG_Q13, REG_Q14, REG_Q15,
			REG_Q16,  REG_Q17, REG_Q18, REG_Q19,  REG_Q20, REG_Q21, REG_Q22, REG_Q23,
			REG_Q24,  REG_Q25, REG_Q26, REG_Q27,  REG_Q28, REG_Q29, REG_Q30, REG_Q31
		};
	}


	virtual vector<uint32_t> GetAllRegisters() override
	{
		vector<uint32_t> r = {
			REG_W0,  REG_W1,  REG_W2,  REG_W3,  REG_W4,  REG_W5,  REG_W6,  REG_W7,
			REG_W8,  REG_W9,  REG_W10, REG_W11, REG_W12, REG_W13, REG_W14, REG_W15,
			REG_W16, REG_W17, REG_W18, REG_W19, REG_W20, REG_W21, REG_W22, REG_W23,
			REG_W24, REG_W25, REG_W26, REG_W27, REG_W28, REG_W29, REG_W30, REG_WSP, REG_WZR,
			REG_X0,  REG_X1,  REG_X2,  REG_X3,  REG_X4,  REG_X5,  REG_X6,  REG_X7,
			REG_X8,  REG_X9,  REG_X10, REG_X11, REG_X12, REG_X13, REG_X14, REG_X15,
			REG_X16, REG_X17, REG_X18, REG_X19, REG_X20, REG_X21, REG_X22, REG_X23,
			REG_X24, REG_X25, REG_X26, REG_X27, REG_X28, REG_X29, REG_X30, REG_SP,  REG_XZR,
			REG_V0,  REG_V1,  REG_V2,  REG_V3,  REG_V4,  REG_V5,  REG_V6,  REG_V7,
			REG_V8,  REG_V9,  REG_V10, REG_V11, REG_V12, REG_V13, REG_V14, REG_V15,
			REG_V16, REG_V17, REG_V18, REG_V19, REG_V20, REG_V21, REG_V22, REG_V23,
			REG_V24, REG_V25, REG_V26, REG_V27, REG_V28, REG_V29, REG_V30, REG_V31,
			REG_B0,  REG_B1,  REG_B2,  REG_B3,  REG_B4,  REG_B5,  REG_B6,  REG_B7,
			REG_B8,  REG_B9,  REG_B10, REG_B11, REG_B12, REG_B13, REG_B14, REG_B15,
			REG_B16, REG_B17, REG_B18, REG_B19, REG_B20, REG_B21, REG_B22, REG_B23,
			REG_B24, REG_B25, REG_B26, REG_B27, REG_B28, REG_B29, REG_B30, REG_B31,
			REG_H0,  REG_H1,  REG_H2,  REG_H3,  REG_H4,  REG_H5,  REG_H6,  REG_H7,
			REG_H8,  REG_H9,  REG_H10, REG_H11, REG_H12, REG_H13, REG_H14, REG_H15,
			REG_H16, REG_H17, REG_H18, REG_H19, REG_H20, REG_H21, REG_H22, REG_H23,
			REG_H24, REG_H25, REG_H26, REG_H27, REG_H28, REG_H29, REG_H30, REG_H31,
			REG_S0,  REG_S1,  REG_S2,  REG_S3,  REG_S4,  REG_S5,  REG_S6,  REG_S7,
			REG_S8,  REG_S9,  REG_S10, REG_S11, REG_S12, REG_S13, REG_S14, REG_S15,
			REG_S16, REG_S17, REG_S18, REG_S19, REG_S20, REG_S21, REG_S22, REG_S23,
			REG_S24, REG_S25, REG_S26, REG_S27, REG_S28, REG_S29, REG_S30, REG_S31,
			REG_D0,  REG_D1,  REG_D2,  REG_D3,  REG_D4,  REG_D5,  REG_D6,  REG_D7,
			REG_D8,  REG_D9,  REG_D10, REG_D11, REG_D12, REG_D13, REG_D14, REG_D15,
			REG_D16, REG_D17, REG_D18, REG_D19, REG_D20, REG_D21, REG_D22, REG_D23,
			REG_D24, REG_D25, REG_D26, REG_D27, REG_D28, REG_D29, REG_D30, REG_D31,
			REG_Q0,  REG_Q1,  REG_Q2,  REG_Q3,  REG_Q4,  REG_Q5,  REG_Q6,  REG_Q7,
			REG_Q8,  REG_Q9,  REG_Q10, REG_Q11, REG_Q12, REG_Q13, REG_Q14, REG_Q15,
			REG_Q16, REG_Q17, REG_Q18, REG_Q19, REG_Q20, REG_Q21, REG_Q22, REG_Q23,
			REG_Q24, REG_Q25, REG_Q26, REG_Q27, REG_Q28, REG_Q29, REG_Q30, REG_Q31
		};

		// this could also be inlined, but the odds of more status registers being added
		// seems high, and updating them multiple places would be a pain
		for (uint32_t ii = SYSREG_NONE + 1; ii < SYSREG_END; ++ii)
			r.push_back(ii);

		for (uint32_t ii = FAKEREG_NONE + 1; ii < FAKEREG_END; ++ii)
			r.push_back(ii);

		return r;
	}


	virtual vector<uint32_t> GetAllFlags() override
	{
		return vector<uint32_t>{
			IL_FLAG_N, IL_FLAG_Z, IL_FLAG_C, IL_FLAG_V
		};
	}


	virtual vector<uint32_t> GetAllFlagWriteTypes() override
	{
		return vector<uint32_t>{
			IL_FLAGWRITE_ALL
		};
	}


	virtual BNRegisterInfo GetRegisterInfo(uint32_t reg) override
	{
		switch (reg)
		{
			case REG_W0:
			case REG_W1:
			case REG_W2:
			case REG_W3:
			case REG_W4:
			case REG_W5:
			case REG_W6:
			case REG_W7:
			case REG_W8:
			case REG_W9:
			case REG_W10:
			case REG_W11:
			case REG_W12:
			case REG_W13:
			case REG_W14:
			case REG_W15:
			case REG_W16:
			case REG_W17:
			case REG_W18:
			case REG_W19:
			case REG_W20:
			case REG_W21:
			case REG_W22:
			case REG_W23:
			case REG_W24:
			case REG_W25:
			case REG_W26:
			case REG_W27:
			case REG_W28:
			case REG_W29:
			case REG_W30:
			case REG_WSP:
			case REG_WZR:
					return RegisterInfo(REG_X0 + (reg-REG_W0), 0, 4, true);
			case REG_X0:
			case REG_X1:
			case REG_X2:
			case REG_X3:
			case REG_X4:
			case REG_X5:
			case REG_X6:
			case REG_X7:
			case REG_X8:
			case REG_X9:
			case REG_X10:
			case REG_X11:
			case REG_X12:
			case REG_X13:
			case REG_X14:
			case REG_X15:
			case REG_X16:
			case REG_X17:
			case REG_X18:
			case REG_X19:
			case REG_X20:
			case REG_X21:
			case REG_X22:
			case REG_X23:
			case REG_X24:
			case REG_X25:
			case REG_X26:
			case REG_X27:
			case REG_X28:
			case REG_X29:
			case REG_X30:
			case REG_SP:
			case REG_XZR:
				return RegisterInfo(reg, 0, 8);
			case REG_V0:
			case REG_V1:
			case REG_V2:
			case REG_V3:
			case REG_V4:
			case REG_V5:
			case REG_V6:
			case REG_V7:
			case REG_V8:
			case REG_V9:
			case REG_V10:
			case REG_V11:
			case REG_V12:
			case REG_V13:
			case REG_V14:
			case REG_V15:
			case REG_V16:
			case REG_V17:
			case REG_V18:
			case REG_V19:
			case REG_V20:
			case REG_V21:
			case REG_V22:
			case REG_V23:
			case REG_V24:
			case REG_V25:
			case REG_V26:
			case REG_V27:
			case REG_V28:
			case REG_V29:
			case REG_V30:
			case REG_V31:
				return RegisterInfo(REG_Q0+(reg-REG_V0), 0, 16);
			case REG_B0:
			case REG_B1:
			case REG_B2:
			case REG_B3:
			case REG_B4:
			case REG_B5:
			case REG_B6:
			case REG_B7:
			case REG_B8:
			case REG_B9:
			case REG_B10:
			case REG_B11:
			case REG_B12:
			case REG_B13:
			case REG_B14:
			case REG_B15:
			case REG_B16:
			case REG_B17:
			case REG_B18:
			case REG_B19:
			case REG_B20:
			case REG_B21:
			case REG_B22:
			case REG_B23:
			case REG_B24:
			case REG_B25:
			case REG_B26:
			case REG_B27:
			case REG_B28:
			case REG_B29:
			case REG_B30:
			case REG_B31:
				return RegisterInfo(REG_Q0+(reg-REG_B0), 0, 1);
			case REG_H0:
			case REG_H1:
			case REG_H2:
			case REG_H3:
			case REG_H4:
			case REG_H5:
			case REG_H6:
			case REG_H7:
			case REG_H8:
			case REG_H9:
			case REG_H10:
			case REG_H11:
			case REG_H12:
			case REG_H13:
			case REG_H14:
			case REG_H15:
			case REG_H16:
			case REG_H17:
			case REG_H18:
			case REG_H19:
			case REG_H20:
			case REG_H21:
			case REG_H22:
			case REG_H23:
			case REG_H24:
			case REG_H25:
			case REG_H26:
			case REG_H27:
			case REG_H28:
			case REG_H29:
			case REG_H30:
			case REG_H31:
				return RegisterInfo(REG_Q0+(reg-REG_H0), 0, 2);
			case REG_S0:
			case REG_S1:
			case REG_S2:
			case REG_S3:
			case REG_S4:
			case REG_S5:
			case REG_S6:
			case REG_S7:
			case REG_S8:
			case REG_S9:
			case REG_S10:
			case REG_S11:
			case REG_S12:
			case REG_S13:
			case REG_S14:
			case REG_S15:
			case REG_S16:
			case REG_S17:
			case REG_S18:
			case REG_S19:
			case REG_S20:
			case REG_S21:
			case REG_S22:
			case REG_S23:
			case REG_S24:
			case REG_S25:
			case REG_S26:
			case REG_S27:
			case REG_S28:
			case REG_S29:
			case REG_S30:
			case REG_S31:
				return RegisterInfo(REG_Q0+(reg-REG_S0), 0, 4);
			case REG_D0:
			case REG_D1:
			case REG_D2:
			case REG_D3:
			case REG_D4:
			case REG_D5:
			case REG_D6:
			case REG_D7:
			case REG_D8:
			case REG_D9:
			case REG_D10:
			case REG_D11:
			case REG_D12:
			case REG_D13:
			case REG_D14:
			case REG_D15:
			case REG_D16:
			case REG_D17:
			case REG_D18:
			case REG_D19:
			case REG_D20:
			case REG_D21:
			case REG_D22:
			case REG_D23:
			case REG_D24:
			case REG_D25:
			case REG_D26:
			case REG_D27:
			case REG_D28:
			case REG_D29:
			case REG_D30:
			case REG_D31:
				return RegisterInfo(REG_Q0+(reg-REG_D0), 0, 8);
			case REG_Q0:
			case REG_Q1:
			case REG_Q2:
			case REG_Q3:
			case REG_Q4:
			case REG_Q5:
			case REG_Q6:
			case REG_Q7:
			case REG_Q8:
			case REG_Q9:
			case REG_Q10:
			case REG_Q11:
			case REG_Q12:
			case REG_Q13:
			case REG_Q14:
			case REG_Q15:
			case REG_Q16:
			case REG_Q17:
			case REG_Q18:
			case REG_Q19:
			case REG_Q20:
			case REG_Q21:
			case REG_Q22:
			case REG_Q23:
			case REG_Q24:
			case REG_Q25:
			case REG_Q26:
			case REG_Q27:
			case REG_Q28:
			case REG_Q29:
			case REG_Q30:
			case REG_Q31:
				return RegisterInfo(reg, 0, 16);
			case FAKEREG_SYSCALL_IMM:
				return RegisterInfo(reg, 0, 2);
		}

		if (reg > SYSREG_NONE && reg < SYSREG_END)
			return RegisterInfo(reg, 0, 4);

		return RegisterInfo(0, 0, 0);
	}

	virtual uint32_t GetStackPointerRegister() override
	{
		return REG_SP;
	}

	virtual uint32_t GetLinkRegister() override
	{
		return REG_X30;
	}

	virtual vector<uint32_t> GetSystemRegisters() override {
		vector<uint32_t> system_regs = {};

		for (uint32_t ii = SYSREG_NONE + 1; ii < SYSREG_END; ++ii) {
			system_regs.push_back(ii);
		}

		return system_regs;
	}
};


class Arm64ImportedFunctionRecognizer: public FunctionRecognizer
{
private:
	bool RecognizeELFPLTEntries(BinaryView* data, Function* func, LowLevelILFunction* il)
	{
		// Look for the following code pattern:
		// x16.q = plt
		// x17.q = [add.q(x16.q, pltoffset)].q || x17.q = [x16.q].q
		// x16.q = add.q(x16.q, pltoffset) || x16.q = x16.q
		// jump(x17.q)

		if (il->GetInstructionCount() < 4)
			return false;

		LowLevelILInstruction adrp = il->GetInstruction(0);
		if (adrp.operation != LLIL_SET_REG)
			return false;
		LowLevelILInstruction adrpOperand = adrp.GetSourceExpr<LLIL_SET_REG>();
		if (!LowLevelILFunction::IsConstantType(adrpOperand.operation))
			return false;
		if (adrpOperand.size != func->GetArchitecture()->GetAddressSize())
			return false;
		uint64_t pltPage = adrpOperand.GetConstant();
		uint32_t pltReg = adrp.GetDestRegister<LLIL_SET_REG>();

		LowLevelILInstruction ld = il->GetInstruction(1);
		if (ld.operation != LLIL_SET_REG)
			return false;
		LowLevelILInstruction ldOperand = ld.GetSourceExpr<LLIL_SET_REG>();
		if (ldOperand.operation != LLIL_LOAD)
			return false;
		if (ldOperand.size != func->GetArchitecture()->GetAddressSize())
			return false;
		LowLevelILInstruction ldAddrOperand = ldOperand.GetSourceExpr<LLIL_LOAD>();
		uint64_t entry = pltPage;
		uint64_t targetReg;
		int64_t ldAddrRightOperandValue = 0;
		if (ldAddrOperand.operation == LLIL_ADD)
		{
			LowLevelILInstruction ldAddrLeftOperand = ldAddrOperand.GetLeftExpr<LLIL_ADD>();
			LowLevelILInstruction ldAddrRightOperand = ldAddrOperand.GetRightExpr<LLIL_ADD>();
			if (ldAddrLeftOperand.operation != LLIL_REG)
				return false;
			if (ldAddrLeftOperand.GetSourceRegister<LLIL_REG>() != pltReg)
				return false;

			if (!LowLevelILFunction::IsConstantType(ldAddrRightOperand.operation))
				return false;
			ldAddrRightOperandValue = ldAddrRightOperand.GetConstant();
			entry = pltPage + ldAddrRightOperandValue;
		}
		else if (ldAddrOperand.operation != LLIL_REG) //If theres no constant
			return false;

		targetReg = ld.GetDestRegister<LLIL_SET_REG>();
		Ref<Symbol> sym = data->GetSymbolByAddress(entry);
		if (!sym)
			return false;
		if (sym->GetType() != ImportAddressSymbol)
			return false;

		LowLevelILInstruction add = il->GetInstruction(2);
		if (add.operation != LLIL_SET_REG)
			return false;
		if (add.GetDestRegister<LLIL_SET_REG>() != pltReg)
			return false;
		LowLevelILInstruction addOperand = add.GetSourceExpr<LLIL_SET_REG>();

		if (addOperand.operation == LLIL_ADD)
		{
			LowLevelILInstruction addLeftOperand = addOperand.GetLeftExpr<LLIL_ADD>();
			LowLevelILInstruction addRightOperand = addOperand.GetRightExpr<LLIL_ADD>();
			if (addLeftOperand.operation != LLIL_REG)
				return false;
			if (addLeftOperand.GetSourceRegister<LLIL_REG>() != pltReg)
				return false;
			if (!LowLevelILFunction::IsConstantType(addRightOperand.operation))
				return false;
			if (addRightOperand.GetConstant() != ldAddrRightOperandValue)
				return false;
		}
		else if ((addOperand.operation != LLIL_REG) || (addOperand.GetSourceRegister<LLIL_REG>() != pltReg)) //Simple assignment
			return false;

		LowLevelILInstruction jump = il->GetInstruction(3);
		if ((jump.operation != LLIL_JUMP) && (jump.operation != LLIL_TAILCALL))
			return false;
		LowLevelILInstruction jumpOperand = (jump.operation == LLIL_JUMP) ? jump.GetDestExpr<LLIL_JUMP>() : jump.GetDestExpr<LLIL_TAILCALL>();
		if (jumpOperand.operation != LLIL_REG)
			return false;
		if (jumpOperand.GetSourceRegister<LLIL_REG>() != targetReg)
			return false;

		Ref<Symbol> funcSym = Symbol::ImportedFunctionFromImportAddressSymbol(sym, func->GetStart());
		data->DefineAutoSymbol(funcSym);
		func->ApplyImportedTypes(funcSym);
		return true;
	}


	bool RecognizeMachoPLTEntries(BinaryView* data, Function* func, LowLevelILFunction* il)
	{
		if ((il->GetInstructionCount() == 2) || (il->GetInstructionCount() == 3))
		{
			//0: nop OR x16 = symbol@PLT
			//1: x16 = [symbol@PLT]
			//2: jump(x16)
			size_t instrIndex = 0;
			if (il->GetInstructionCount() == 3)
			{
				//check that the first instruction is a nop
				LowLevelILInstruction insn = il->GetInstruction(instrIndex++);
				if ((insn.operation != LLIL_NOP) && (insn.operation != LLIL_SET_REG))
					return false;
			}

			//check that the second operation is a set register
			LowLevelILInstruction load = il->GetInstruction(instrIndex++);
			if (load.operation != LLIL_SET_REG)
				return false;

			//check that the rhs is a load operand
			LowLevelILInstruction loadOperand = load.GetSourceExpr<LLIL_SET_REG>();
			if (loadOperand.operation != LLIL_LOAD)
				return false;

			//ensure that the operand is the same size as the address
			if (loadOperand.size != func->GetArchitecture()->GetAddressSize())
				return false;

			//ensure that what we are loading is a const
			RegisterValue loadAddrConstant = loadOperand.GetValue();
			if (loadAddrConstant.state != ImportedAddressValue)
				return false;

			//check if the type of symbol is a PLT symbol
			Ref<Symbol> sym = data->GetSymbolByAddress(loadAddrConstant.value);
			if (!sym || ((sym->GetType() != ImportAddressSymbol) && (sym->GetType() != ImportedDataSymbol)))
				return false;

			//we have what looks like a PLT entry, record the targetReg
			uint32_t targetReg = load.GetDestRegister<LLIL_SET_REG>();

			//ensure we have a jump instruction
			LowLevelILInstruction jump = il->GetInstruction(instrIndex++);
			if ((jump.operation != LLIL_JUMP) && (jump.operation != LLIL_TAILCALL))
				return false;

			//ensure we are jumping to a register
			LowLevelILInstruction jumpOperand = (jump.operation == LLIL_JUMP) ? jump.GetDestExpr<LLIL_JUMP>() : jump.GetDestExpr<LLIL_TAILCALL>();
			if (jumpOperand.operation != LLIL_REG)
				return false;

			//is the jump target our target register?
			if (jumpOperand.GetSourceRegister<LLIL_REG>() != targetReg)
				return false;

			data->DefineImportedFunction(sym, func);
			return true;
		}
		else if (il->GetInstructionCount() == 4)
		{
			//0: x17 = symbol@PLT (hi)
			//1: x17 = x17 + symbol@PLT (lo)
			//2: x16 = [symbol@PLT]
			//3: tailcall(x16)
			size_t instrIndex = 0;

			//check that the first operation is a set register
			LowLevelILInstruction setTemp = il->GetInstruction(instrIndex++);
			if (setTemp.operation != LLIL_SET_REG)
				return false;

			uint32_t tempReg = setTemp.GetDestRegister<LLIL_SET_REG>();

			//check that the rhs is a constant
			LowLevelILInstruction temp = setTemp.GetSourceExpr<LLIL_SET_REG>();
			if (!LowLevelILFunction::IsConstantType(temp.operation))
				return false;

			LowLevelILInstruction finalAddress = il->GetInstruction(instrIndex++);
			if (finalAddress.operation != LLIL_SET_REG)
				return false;

			if (tempReg != finalAddress.GetDestRegister<LLIL_SET_REG>())
				return false;

			//check that the second operation is a set register
			LowLevelILInstruction load = il->GetInstruction(instrIndex++);
			if (load.operation != LLIL_SET_REG)
				return false;

			//check that the rhs is a load operand
			LowLevelILInstruction loadOperand = load.GetSourceExpr<LLIL_SET_REG>();
			if (loadOperand.operation != LLIL_LOAD)
				return false;

			//ensure that the operand is the same size as the address
			if (loadOperand.size != func->GetArchitecture()->GetAddressSize())
				return false;

			//ensure that what we are loading is a const
			LowLevelILInstruction loadAddrOperand = loadOperand.GetSourceExpr<LLIL_LOAD>();
			if (loadAddrOperand.operation != LLIL_REG || loadAddrOperand.GetSourceRegister<LLIL_REG>() != tempReg)
				return false;

			RegisterValue loadAddrConstant = loadOperand.GetValue();
			if (loadAddrConstant.state != ImportedAddressValue)
				return false;

			//check if the type of symbol is a PLT/GOT symbol
			Ref<Symbol> sym = data->GetSymbolByAddress(loadAddrConstant.value);
			if (!sym || ((sym->GetType() != ImportAddressSymbol) && (sym->GetType() != ImportedDataSymbol)))
				return false;

			//we have what looks like a PLT entry, record the targetReg
			uint32_t targetReg = load.GetDestRegister<LLIL_SET_REG>();

			//ensure we have a jump instruction
			LowLevelILInstruction jump = il->GetInstruction(instrIndex++);
			if ((jump.operation != LLIL_JUMP) && (jump.operation != LLIL_TAILCALL))
				return false;

			//ensure we are jumping to a register
			LowLevelILInstruction jumpOperand = (jump.operation == LLIL_JUMP) ? jump.GetDestExpr<LLIL_JUMP>() : jump.GetDestExpr<LLIL_TAILCALL>();
			if (jumpOperand.operation != LLIL_REG)
				return false;

			//is the jump target our target register?
			if (jumpOperand.GetSourceRegister<LLIL_REG>() != targetReg)
				return false;

			data->DefineImportedFunction(sym, func);
			return true;
		}

		return false;
	}


public:
	virtual bool RecognizeLowLevelIL(BinaryView* data, Function* func, LowLevelILFunction* il) override
	{
		if (RecognizeELFPLTEntries(data, func, il))
			return true;
		else if (RecognizeMachoPLTEntries(data, func, il))
			return true;
		return false;
	}
};


class Arm64CallingConvention: public CallingConvention
{
public:
	Arm64CallingConvention(Architecture* arch): CallingConvention(arch, "cdecl")
	{
	}


	virtual vector<uint32_t> GetIntegerArgumentRegisters() override
	{
		return vector<uint32_t>{ REG_X0, REG_X1, REG_X2, REG_X3, REG_X4, REG_X5, REG_X6, REG_X7 };
	}


	virtual vector<uint32_t> GetFloatArgumentRegisters() override
	{
		return vector<uint32_t> { REG_Q0, REG_Q1, REG_Q2, REG_Q3, REG_Q4, REG_Q5, REG_Q6, REG_Q7 };
	}


	virtual vector<uint32_t> GetCallerSavedRegisters() override
	{
		return vector<uint32_t>{ REG_X0, REG_X1, REG_X2, REG_X3, REG_X4, REG_X5, REG_X6, REG_X7,
			REG_X8, REG_X9, REG_X10, REG_X11, REG_X12, REG_X13, REG_X14, REG_X15, REG_X16, REG_X17,
			REG_X18, REG_X30, REG_Q0, REG_Q1, REG_Q2, REG_Q3, REG_Q4, REG_Q5, REG_Q6, REG_Q7,
			REG_Q16, REG_Q17, REG_Q18, REG_Q19, REG_Q20, REG_Q21, REG_Q22, REG_Q23, REG_Q24,
			REG_Q25, REG_Q26, REG_Q27, REG_Q28, REG_Q29, REG_Q30, REG_Q31 };
	}


	virtual vector<uint32_t> GetCalleeSavedRegisters() override
	{
		return vector<uint32_t>{ REG_X19, REG_X20, REG_X21, REG_X22, REG_X23, REG_X24, REG_X25,
			REG_X26, REG_X27, REG_X28, REG_X29 };
	}


	virtual uint32_t GetIntegerReturnValueRegister() override
	{
		return REG_X0;
	}


	virtual uint32_t GetFloatReturnValueRegister() override
	{
		return REG_Q0;
	}
};


class LinuxArm64SystemCallConvention: public CallingConvention
{
public:
	LinuxArm64SystemCallConvention(Architecture* arch): CallingConvention(arch, "linux-syscall")
	{
	}


	virtual vector<uint32_t> GetIntegerArgumentRegisters() override
	{
		return vector<uint32_t>{ REG_X8, REG_X0, REG_X1, REG_X2, REG_X3, REG_X4, REG_X5 };
	}


	virtual vector<uint32_t> GetCallerSavedRegisters() override
	{
		return vector<uint32_t>{ REG_X0 };
	}


	virtual vector<uint32_t> GetCalleeSavedRegisters() override
	{
		return vector<uint32_t>{ REG_X19, REG_X20, REG_X21, REG_X22, REG_X23, REG_X24, REG_X25,
			REG_X26, REG_X27, REG_X28, REG_X29 };
	}


	virtual uint32_t GetIntegerReturnValueRegister() override
	{
		return REG_X0;
	}
};

class WindowsArm64SystemCallConvention: public CallingConvention
{
public:
	WindowsArm64SystemCallConvention(Architecture* arch): CallingConvention(arch, "windows-syscall")
	{
	}


	virtual vector<uint32_t> GetIntegerArgumentRegisters() override
	{
		return { FAKEREG_SYSCALL_IMM };
	}


	virtual vector<uint32_t> GetCallerSavedRegisters() override
	{
		return vector<uint32_t>{ REG_X0 };
	}


	virtual vector<uint32_t> GetCalleeSavedRegisters() override
	{
		return {};
	}


	virtual uint32_t GetIntegerReturnValueRegister() override
	{
		return REG_X0;
	}
};

class MacosArm64SystemCallConvention: public CallingConvention
{
public:
	MacosArm64SystemCallConvention(Architecture* arch): CallingConvention(arch, "macos-syscall")
	{
	}


	virtual vector<uint32_t> GetIntegerArgumentRegisters() override
	{
		return vector<uint32_t>{ REG_X16, REG_X0, REG_X1, REG_X2, REG_X3, REG_X4, REG_X5 };
	}


	virtual vector<uint32_t> GetCallerSavedRegisters() override
	{
		return vector<uint32_t>{ REG_X0 };
	}


	virtual vector<uint32_t> GetCalleeSavedRegisters() override
	{
		return vector<uint32_t>{ REG_X19, REG_X20, REG_X21, REG_X22, REG_X23, REG_X24, REG_X25,
			REG_X26, REG_X27, REG_X28, REG_X29 };
	}


	virtual uint32_t GetIntegerReturnValueRegister() override
	{
		return REG_X0;
	}
};

class Arm64MachoRelocationHandler: public RelocationHandler
{
public:
	virtual bool ApplyRelocation(Ref<BinaryView> view, Ref<Architecture> arch, Ref<Relocation> reloc, uint8_t* dest,
		size_t len) override
	{
		(void)view;
		(void)arch;
		(void)len;

		auto info = reloc->GetInfo();
		if (info.nativeType == (uint64_t) -2) // Magic number defined in MachOView.cpp
			*(uint64_t *) dest = info.target;

		return true;
	}

	virtual bool GetRelocationInfo(Ref<BinaryView> view, Ref<Architecture> arch, vector<BNRelocationInfo>& result) override
	{
		(void)view;
		(void)arch;
		set<MachoArm64RelocationType> unsupportedRelocations;
		for (size_t i = 0; i < result.size(); i++)
		{
			result[i].type = StandardRelocationType;
			switch (result[i].nativeType)
			{
			case ARM64_RELOC_UNSIGNED:
				result[i].pcRelative = false;
				result[i].baseRelative = false;
				result[i].size = 8;
				result[i].truncateSize = 8;
				result[i].hasSign = false;
				break;
			case ARM64_RELOC_SUBTRACTOR:
				if (i >= result.size() - 1 || result[i + 1].nativeType != ARM64_RELOC_UNSIGNED)
					return false;
				result[i].pcRelative = false;
				result[i].baseRelative = false;
				result[i].size = 8;
				result[i].truncateSize = 8;
				result[i].hasSign = true;
				break;
			case ARM64_RELOC_POINTER_TO_GOT:
				result[i].pcRelative = false;
				result[i].baseRelative = false;
				result[i].size = 8;
				result[i].truncateSize = 8;
				result[i].hasSign = false;
				break;
			case ARM64_RELOC_BRANCH26:
			case ARM64_RELOC_PAGE21:
			case ARM64_RELOC_PAGEOFF12:
			case ARM64_RELOC_GOT_LOAD_PAGE21:
			case ARM64_RELOC_GOT_LOAD_PAGEOFF12:
			case ARM64_RELOC_TLVP_LOAD_PAGE21:
			case ARM64_RELOC_TLVP_LOAD_PAGEOFF12:
			case ARM64_RELOC_ADDEND:
			default:
				result[i].type = UnhandledRelocation;
				unsupportedRelocations.insert((MachoArm64RelocationType)result[i].nativeType);
			}
		}

		for (auto& relocType : unsupportedRelocations)
			LogWarn("Unsupported relocation: %s (%x)", GetRelocationString(relocType), relocType);
		return true;
	}
};


class Arm64ElfRelocationHandler: public RelocationHandler
{
public:
	virtual bool ApplyRelocation(Ref<BinaryView> view, Ref<Architecture> arch, Ref<Relocation> reloc, uint8_t* dest, size_t len) override
	{
		(void)view;
		(void)arch;
		auto info = reloc->GetInfo();
		if (len < info.size)
			return false;
		uint64_t* dest64 = (uint64_t*)dest;
		uint32_t* dest32 = (uint32_t*)dest;
		uint16_t* dest16 = (uint16_t*)dest;
		//auto swap = [&arch](uint32_t x) { return (arch->GetEndianness() == LittleEndian)? x : bswap32(x); };
		uint64_t target = reloc->GetTarget();
		Instruction inst;
		#define PAGE(x) (uint32_t)((x) >> 12)
		#define PAGE_OFF(x) (uint32_t)((x) & 0xfff)
		switch (info.nativeType)
		{
		case R_ARM_NONE:
		case R_AARCH64_NONE:
			return true;
		case R_AARCH64_COPY:
		case R_AARCH64_GLOB_DAT:
		case R_AARCH64_JUMP_SLOT:
			dest64[0] = target;
			break;
		case R_AARCH64_ADR_PREL_LO21:
			break;
		case R_AARCH64_ADR_PREL_PG_HI21:
		{
			PC_REL_ADDRESSING* decode = (PC_REL_ADDRESSING*)dest;
			aarch64_decompose(dest32[0], &inst, reloc->GetAddress());
			uint32_t imm = PAGE(info.addend + target) - PAGE(reloc->GetAddress());
			decode->immhi = imm >> 2;
			decode->immlo = imm & 3;
			break;
		}
		case R_AARCH64_ADR_PREL_PG_HI21_NC:
			break;
		case R_AARCH64_ADD_ABS_LO12_NC:
		{
			ADD_SUB_IMM* decode = (ADD_SUB_IMM*)dest;
			aarch64_decompose(dest32[0], &inst, reloc->GetAddress());
			decode->imm = inst.operands[2].immediate + target;
			break;
		}
		case R_AARCH64_CALL26:
		case R_AARCH64_JUMP26:
		{
			UNCONDITIONAL_BRANCH* decode = (UNCONDITIONAL_BRANCH*)dest;
			aarch64_decompose(dest32[0], &inst, 0);
			decode->imm = (inst.operands[0].immediate + target - reloc->GetAddress()) >> 2;
			break;
		}
		case R_AARCH64_ABS16:
			dest16[0] = (uint16_t)(target + info.addend);
			break;
		case R_AARCH64_ABS32:
			dest32[0] = (uint32_t)(target + info.addend);
			break;
		case R_AARCH64_ABS64:
			dest64[0] = target + info.addend;
			break;
		case R_AARCH64_PREL16:
			dest16[0] = (uint16_t)(info.addend + target - reloc->GetAddress());
			break;
		case R_AARCH64_PREL32:
			dest32[0] = (uint32_t)(info.addend + target - reloc->GetAddress());
			break;
		case R_AARCH64_PREL64:
			dest64[0] = info.addend + target - reloc->GetAddress();
			break;
		case R_AARCH64_RELATIVE:
			dest64[0] = target + info.addend;
			break;
		case R_AARCH64_LDST8_ABS_LO12_NC:
		{
			LDST_REG_UNSIGNED_IMM* decode = (LDST_REG_UNSIGNED_IMM*)dest;
			decode->imm = ((target + info.addend) & 0xfff);
			break;
		}
		case R_AARCH64_LDST16_ABS_LO12_NC:
		{
			LDST_REG_UNSIGNED_IMM* decode = (LDST_REG_UNSIGNED_IMM*)dest;
			decode->imm = ((target + info.addend) & 0xffe) >> 1;
			break;
		}
		case R_AARCH64_LDST32_ABS_LO12_NC:
		{
			LDST_REG_UNSIGNED_IMM* decode = (LDST_REG_UNSIGNED_IMM*)dest;
			decode->imm = ((target + info.addend) & 0xffc) >> 2;
			break;
		}
		case R_AARCH64_LDST64_ABS_LO12_NC:
		{
			LDST_REG_UNSIGNED_IMM* decode = (LDST_REG_UNSIGNED_IMM*)dest;
			decode->imm = ((target + info.addend) & 0xff8) >> 3;
			break;
		}
		case R_AARCH64_LDST128_ABS_LO12_NC:
		{
			LDST_REG_UNSIGNED_IMM* decode = (LDST_REG_UNSIGNED_IMM*)dest;
			decode->imm = ((target + info.addend) & 0xff0) >> 4;
			break;
		}
		case R_AARCH64_ADR_GOT_PAGE:
		{
			PC_REL_ADDRESSING* decode = (PC_REL_ADDRESSING*)dest;
			aarch64_decompose(dest32[0], &inst, reloc->GetAddress());
			uint32_t imm = PAGE(info.addend + target) - PAGE(reloc->GetAddress());
			decode->immhi = imm >> 2;
			decode->immlo = imm & 3;
			break;
		}
		case R_AARCH64_LD64_GOT_LO12_NC:
		{
			LDST_REG_UNSIGNED_IMM* decode = (LDST_REG_UNSIGNED_IMM*)dest;
			decode->imm = ((target + info.addend) & 0xff8) >> 3;
			break;
		}
		case R_AARCH64_MOVW_UABS_G0:
		case R_AARCH64_MOVW_UABS_G0_NC:
		case R_AARCH64_MOVW_UABS_G1:
		case R_AARCH64_MOVW_UABS_G1_NC:
		case R_AARCH64_MOVW_UABS_G2:
		case R_AARCH64_MOVW_UABS_G2_NC:
		case R_AARCH64_MOVW_UABS_G3:
		case R_AARCH64_MOVW_SABS_G0:
		case R_AARCH64_MOVW_SABS_G1:
		case R_AARCH64_MOVW_SABS_G2:
		case R_AARCH64_LD_PREL_LO19:
		case R_AARCH64_TSTBR14:
		case R_AARCH64_CONDBR19:
		case R_AARCH64_MOVW_PREL_G0:
		case R_AARCH64_MOVW_PREL_G0_NC:
		case R_AARCH64_MOVW_PREL_G1:
		case R_AARCH64_MOVW_PREL_G1_NC:
		case R_AARCH64_MOVW_PREL_G2:
		case R_AARCH64_MOVW_PREL_G2_NC:
		case R_AARCH64_MOVW_PREL_G3:
		case R_AARCH64_TLS_TPREL64:
		case R_AARCH64_TLS_DTPREL32:
		case R_AARCH64_IRELATIVE:
			return false;
		}
		return true;
	}

	virtual bool GetRelocationInfo(Ref<BinaryView> view, Ref<Architecture> arch, vector<BNRelocationInfo>& result) override
	{
		(void)view; (void)arch; (void)result;
		set<uint64_t> relocTypes;
		for (auto& reloc : result)
		{
			reloc.type = StandardRelocationType;
			reloc.size = 4;
			switch (reloc.nativeType)
			{
			case R_AARCH64_COPY:
				reloc.type = ELFCopyRelocationType;
				reloc.size = 8;
				break;
			case R_AARCH64_GLOB_DAT:
				reloc.type = ELFGlobalRelocationType;
				reloc.size = 8;
				break;
			case R_AARCH64_JUMP_SLOT:
				reloc.type = ELFJumpSlotRelocationType;
				reloc.size = 8;
				break;
			case R_AARCH64_ABS16:
				reloc.pcRelative = false;
				reloc.size = 2;
				break;
			case R_AARCH64_PREL16:
				reloc.pcRelative = true;
				reloc.size = 2;
				break;
			case R_AARCH64_PREL32:
			case R_AARCH64_ADR_PREL_PG_HI21:
			case R_AARCH64_CALL26:
			case R_AARCH64_JUMP26:
				reloc.pcRelative = true;
				reloc.size = 4;
				break;
			case R_AARCH64_ABS32:
			case R_AARCH64_ADD_ABS_LO12_NC:
			case R_AARCH64_LDST8_ABS_LO12_NC:
			case R_AARCH64_LDST16_ABS_LO12_NC:
			case R_AARCH64_LDST32_ABS_LO12_NC:
			case R_AARCH64_LDST64_ABS_LO12_NC:
			case R_AARCH64_LDST128_ABS_LO12_NC:
			case R_AARCH64_ADR_GOT_PAGE:
			case R_AARCH64_LD64_GOT_LO12_NC:
				reloc.pcRelative = false;
				reloc.size = 4;
				break;
			case R_AARCH64_ABS64:
				reloc.pcRelative = false;
				reloc.size = 8;
				break;
			case R_AARCH64_RELATIVE:
				reloc.pcRelative = true;
				reloc.size = 8;
				break;
			default:
				reloc.type = UnhandledRelocation;
				relocTypes.insert(reloc.nativeType);
				break;
			}
		}
		for (auto& reloc : relocTypes)
			LogWarn("Unsupported ELF relocation type: %s", GetRelocationString((ElfArm64RelocationType)reloc));
		return true;
	}

	virtual size_t GetOperandForExternalRelocation(const uint8_t* data, uint64_t addr, size_t length,
		Ref<LowLevelILFunction> il, Ref<Relocation> relocation) override
	{
		(void)data;
		(void)addr;
		(void)length;
		(void)il;
		auto info = relocation->GetInfo();
		switch (info.nativeType)
		{
		case R_AARCH64_ADR_PREL_PG_HI21:
			return BN_NOCOERCE_EXTERN_PTR;
		default:
			return BN_AUTOCOERCE_EXTERN_PTR;
		}
	}
};


class Arm64PeRelocationHandler: public RelocationHandler
{
public:
	virtual bool GetRelocationInfo(Ref<BinaryView> view, Ref<Architecture> arch, vector<BNRelocationInfo>& result) override
	{
		(void)view;
		(void)arch;
		set<uint64_t> relocTypes;
		for (auto& reloc : result)
		{
			reloc.type = UnhandledRelocation;
			relocTypes.insert(reloc.nativeType);
		}
		for (auto& reloc : relocTypes)
			LogWarn("Unsupported PE relocation type: %s", GetRelocationString((PeArm64RelocationType)reloc));
		return false;
	}
};


extern "C"
{
#ifdef DEMO_VERSION
	bool Arm64PluginInit()
#else
	BINARYNINJAPLUGIN bool CorePluginInit()
#endif
	{
		Architecture* arm64 = new Arm64Architecture();

		Architecture::Register(arm64);

		// Register calling convention
		Ref<CallingConvention> conv;
		conv = new Arm64CallingConvention(arm64);
		arm64->RegisterCallingConvention(conv);
		arm64->SetDefaultCallingConvention(conv);
		arm64->SetCdeclCallingConvention(conv);
		arm64->SetFastcallCallingConvention(conv);
		arm64->SetStdcallCallingConvention(conv);

		conv = new LinuxArm64SystemCallConvention(arm64);
		arm64->RegisterCallingConvention(conv);

		conv = new WindowsArm64SystemCallConvention(arm64);
		arm64->RegisterCallingConvention(conv);

		// Register ARM64 specific PLT trampoline recognizer
		arm64->RegisterFunctionRecognizer(new Arm64ImportedFunctionRecognizer());

		// Register ARM64 Relocation handlers
		arm64->RegisterRelocationHandler("Mach-O", new Arm64MachoRelocationHandler());
		arm64->RegisterRelocationHandler("ELF", new Arm64ElfRelocationHandler());
		arm64->RegisterRelocationHandler("PE", new Arm64PeRelocationHandler());

		// Register the architectures with the binary format parsers so that they know when to use
		// these architectures for disassembling an executable file
		BinaryViewType::RegisterArchitecture("Mach-O", 0x0100000c, LittleEndian, arm64);
		BinaryViewType::RegisterArchitecture("ELF", 0xb7, LittleEndian, arm64);
		BinaryViewType::RegisterArchitecture("PE", 0xaa64, LittleEndian, arm64);
		arm64->SetBinaryViewTypeConstant("ELF", "R_COPY", 0x400);
		arm64->SetBinaryViewTypeConstant("ELF", "R_JUMP_SLOT", 0x402);

		return true;
	}
}

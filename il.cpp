#include <stdarg.h>
#include <cstring>
#include <inttypes.h>
#include "lowlevelilinstruction.h"

#include "sysregs.h"
#include "il.h"

using namespace BinaryNinja;

#define IMM(X) X.immediate
#define REG(X) (X).reg[0]
#define REGSZ(X) get_register_size(REG(X))
#define ILREG(X) ExtractRegister(il, X, 0, REGSZ(X), false, REGSZ(X))
#define ILCONST(X) il.Const(REGSZ(X), IMM(X))
#define SETREG(R,V) il.AddInstruction(il.SetRegister(REGSZ(R), REG(R), V))
#define ADDREGOFS(R,O) il.Add(REGSZ(R), ILREG(R), il.Const(REGSZ(R), O))
#define ADDREGREG(R1,R2) il.Add(REGSZ(R1), ILREG(R1), ILREG(R2))
#define ONES(N) (-1ULL >> (64-N))
#define SETFLAGS (instr.setflags ? IL_FLAGWRITE_ALL : IL_FLAGWRITE_NONE)

#define ABORT_LIFT \
{ \
	il.AddInstruction(il.Unimplemented()); \
	break; \
}

static ExprId GetCondition(LowLevelILFunction& il, Condition cond)
{
	switch(cond)
	{
		case COND_EQ: return il.FlagCondition(LLFC_E);
		case COND_NE: return il.FlagCondition(LLFC_NE);
		case COND_CS: return il.FlagCondition(LLFC_UGE);
		case COND_CC: return il.FlagCondition(LLFC_ULT);
		case COND_MI: return il.FlagCondition(LLFC_NEG);
		case COND_PL: return il.FlagCondition(LLFC_POS);
		case COND_VS: return il.FlagCondition(LLFC_O);
		case COND_VC: return il.FlagCondition(LLFC_NO);
		case COND_HI: return il.FlagCondition(LLFC_UGT);
		case COND_LS: return il.FlagCondition(LLFC_ULE);
		case COND_GE: return il.FlagCondition(LLFC_SGE);
		case COND_LT: return il.FlagCondition(LLFC_SLT);
		case COND_GT: return il.FlagCondition(LLFC_SGT);
		case COND_LE: return il.FlagCondition(LLFC_SLE);
		case COND_AL: return il.Const(0, 1); //Always branch
		case COND_NV:
		default:
			return il.Const(0, 0); //Never branch
	}
}


static void GenIfElse(LowLevelILFunction& il, ExprId clause, ExprId trueCase, ExprId falseCase)
{
	if(falseCase) {
		LowLevelILLabel trueCode, falseCode, done;
		il.AddInstruction(il.If(clause, trueCode, falseCode));
		il.MarkLabel(trueCode);
		il.AddInstruction(trueCase);
		il.AddInstruction(il.Goto(done));
		il.MarkLabel(falseCode);
		il.AddInstruction(falseCase);
		il.AddInstruction(il.Goto(done));
		il.MarkLabel(done);
	}
	else {
		LowLevelILLabel trueCode, done;
		il.AddInstruction(il.If(clause, trueCode, done));
		il.MarkLabel(trueCode);
		il.AddInstruction(trueCase);
		il.MarkLabel(done);
	}
	return;
}


static ExprId ExtractRegister(LowLevelILFunction& il, InstructionOperand& operand, size_t regNum, size_t extractSize, bool signExtend, size_t resultSize)
{
	size_t opsz = get_register_size(operand.reg[regNum]);

	switch (operand.reg[regNum]) {
		case REG_WZR:
		case REG_XZR:
			return il.Const(resultSize, 0);
		default:
			break;
	}

	ExprId res = 0;

	switch (operand.operandClass) {
	case SYS_REG:
		res = il.Register(opsz, operand.sysreg);
		break;
	case REG:
	default:
		res = il.Register(opsz, operand.reg[regNum]);
		break;
	}

	if (extractSize < opsz)
		res = il.LowPart(extractSize, res);

	if (extractSize < resultSize || opsz < extractSize)
	{
		if (signExtend)
			res = il.SignExtend(resultSize, res);
		else
			res = il.ZeroExtend(resultSize, res);
	}

	return res;
}

static ExprId GetFloat(LowLevelILFunction& il, Instruction& instr, InstructionOperand& operand)
{
	ExprId res;

	switch(instr.datasize) {
		case 16:
			res = il.FloatConstRaw(2, operand.immediate);
			break;
		case 32:
			res = il.FloatConstSingle(*(float *)&(operand.immediate));
			break;
		case 64:
			res = il.FloatConstDouble(*(double *)&(operand.immediate));
			break;
		default:
			res = il.Unimplemented();
	}

	return res;
}

static ExprId GetShiftedRegister(LowLevelILFunction& il, InstructionOperand& operand, size_t regNum, size_t resultSize)
{
	ExprId res;

	// peel off the variants that return early
	switch (operand.shiftType)
	{
		case ShiftType_NONE:
			res = ExtractRegister(il, operand, regNum, REGSZ(operand), false, resultSize);
			return res;
		case ShiftType_ASR:
			res = ExtractRegister(il, operand, regNum, REGSZ(operand), false, resultSize);
			if (operand.shiftValue)
				res = il.ArithShiftRight(resultSize, res,
						il.Const(0, operand.shiftValue));
			return res;
		case ShiftType_LSR:
			res = ExtractRegister(il, operand, regNum, REGSZ(operand), false, resultSize);
			if (operand.shiftValue)
				res = il.LogicalShiftRight(resultSize, res,
						il.Const(1, operand.shiftValue));
			return res;
		case ShiftType_ROR:
			res = ExtractRegister(il, operand, regNum, REGSZ(operand), false, resultSize);
			if (operand.shiftValue)
				res = il.RotateRight(resultSize, res,
						il.Const(1, operand.shiftValue));
			return res;
		default:
			break;
	}

	// everything else falls through to maybe be left shifted
	switch (operand.shiftType)
	{
		case ShiftType_LSL:
			res = ExtractRegister(il, operand, regNum, REGSZ(operand), false, resultSize);
			break;
		case ShiftType_SXTB:
			res = ExtractRegister(il, operand, regNum, 1, true, resultSize);
			break;
		case ShiftType_SXTH:
			res = ExtractRegister(il, operand, regNum, 2, true, resultSize);
			break;
		case ShiftType_SXTW:
			res = ExtractRegister(il, operand, regNum, 4, true, resultSize);
			break;
		case ShiftType_SXTX:
			res = ExtractRegister(il, operand, regNum, 8, true, resultSize);
			break;
		case ShiftType_UXTB:
			res = ExtractRegister(il, operand, regNum, 1, false, resultSize);
			break;
		case ShiftType_UXTH:
			res = ExtractRegister(il, operand, regNum, 2, false, resultSize);
			break;
		case ShiftType_UXTW:
			res = ExtractRegister(il, operand, regNum, 4, false, resultSize);
			break;
		case ShiftType_UXTX:
			res = ExtractRegister(il, operand, regNum, 8, false, resultSize);
			break;
		default:
			il.AddInstruction(il.Unimplemented());
			return il.Unimplemented();
	}

	if (operand.shiftValue)
		res = il.ShiftLeft(resultSize, res,
				il.Const(1, operand.shiftValue));

	return res;
}

static ExprId GetILOperandPreOrPostIndex(LowLevelILFunction& il, InstructionOperand& operand)
{
	if(operand.operandClass!=MEM_PRE_IDX && operand.operandClass!=MEM_POST_IDX)
		return 0;

	if(operand.reg[1] == REG_NONE) {
		// ..., [Xn], #imm
		if(IMM(operand) == 0)
			return 0;

		return il.SetRegister(REGSZ(operand), REG(operand),
			il.Add(REGSZ(operand), ILREG(operand),
				il.Const(REGSZ(operand), IMM(operand))));
	}
	else {
		// ..., [Xn], <Xm>
		return il.SetRegister(REGSZ(operand), REG(operand),
			il.Add(REGSZ(operand), ILREG(operand), il.Register(8, operand.reg[1])));
	}
}

/* Returns an expression that does any pre-incrementing on an operand, if it exists */
static ExprId GetILOperandPreIndex(LowLevelILFunction& il, InstructionOperand& operand)
{
	if(operand.operandClass != MEM_PRE_IDX)
		return 0;

	return GetILOperandPreOrPostIndex(il, operand);
}

/* Returns an expression that does any post-incrementing on an operand, if it exists */
static ExprId GetILOperandPostIndex(LowLevelILFunction& il, InstructionOperand& operand)
{
	if(operand.operandClass != MEM_POST_IDX)
		return 0;

	return GetILOperandPreOrPostIndex(il, operand);
}

/* Returns an IL expression that reads (and only reads) from the operand.
	It accounts for, but does not generate IL that executes, pre and post indexing.
	The operand class can be overridden.
	An additional offset can be applied, convenient for calculating sequential loads and stores. */
static ExprId GetILOperandEffectiveAddress(LowLevelILFunction& il, InstructionOperand& operand, size_t addrSize, OperandClass oclass, size_t extra_offset)
{
	ExprId addr = 0;
	if(oclass == NONE)
		oclass = operand.operandClass;
	switch (oclass) {
		case MEM_REG: // ldr x0, [x1]
		case MEM_POST_IDX: // ldr w0, [x1], #4
			addr = il.Register(addrSize, operand.reg[0]);
			if(extra_offset)
				addr = il.Add(addrSize, addr, il.Const(addrSize, extra_offset));
			break;
		case MEM_OFFSET: // ldr w0, [x1, #4]
		case MEM_PRE_IDX: // ldr w0, [x1, #4]!
			addr = il.Add(addrSize, il.Register(addrSize, operand.reg[0]), il.Const(addrSize, operand.immediate + extra_offset));
			break;
		case MEM_EXTENDED:
			if(operand.shiftType == ShiftType_NONE) {
				addr = il.Add(addrSize, il.Register(addrSize, operand.reg[0]), il.Const(addrSize, operand.immediate + extra_offset));
			}
			else if (operand.shiftType == ShiftType_LSL) {
				if(extra_offset) {
					addr = il.Add(addrSize, il.Register(addrSize, operand.reg[0]),
						il.Add(addrSize, il.ShiftLeft(addrSize, il.Const(addrSize, operand.immediate), il.Const(0, operand.shiftValue)),
							il.Const(addrSize, extra_offset)));
				}
				else {
					addr = il.Add(addrSize, il.Register(addrSize, operand.reg[0]),
						il.ShiftLeft(addrSize, il.Const(addrSize, operand.immediate), il.Const(0, operand.shiftValue)));
				}
			}
			else {
				//printf("ERROR: dunno how to handle MEM_EXTENDED shiftType %d\n", operand.shiftType);
				ABORT_LIFT;
			}
			break;
		default:
			//printf("ERROR: dunno how to handle operand class %d\n", oclass);
			ABORT_LIFT;
	}
	return addr;
}


static size_t ReadILOperand(LowLevelILFunction& il, InstructionOperand& operand, size_t resultSize)
{
	switch (operand.operandClass)
	{
	case IMM32:
	case IMM64:
		if (operand.shiftType != ShiftType_NONE && operand.shiftValue)
			return il.Const(resultSize, operand.immediate << operand.shiftValue);
		else
			return il.Const(resultSize, operand.immediate);
	case LABEL:
		return il.ConstPointer(8, operand.immediate);
	case REG:
		if (operand.reg[0] == REG_WZR || operand.reg[0] == REG_XZR)
			return il.Const(resultSize, 0);
		return GetShiftedRegister(il, operand, 0, resultSize);
	case MEM_REG:
		return il.Load(resultSize, il.Register(8, operand.reg[0]));
	case MEM_OFFSET:
		if (operand.immediate != 0)
			return il.Load(resultSize, il.Add(8, il.Register(8, operand.reg[0]), il.Const(8, operand.immediate)));
		else
			return il.Load(resultSize, il.Register(8, operand.reg[0]));
	case MEM_EXTENDED:
		return il.Load(resultSize, GetILOperandEffectiveAddress(il, operand, resultSize, NONE, 0));
	case MEM_PRE_IDX:
	case MEM_POST_IDX:
	case MULTI_REG:
	case FIMM32:
	case NONE:
	default:
		return il.Unimplemented();
	}
}


unsigned v_unpack_lookup_sz[15] = { 0, 1, 2, 4, 8, 16, 1, 2, 4, 8, 1, 2, 4, 1, 1 };

Register *v_unpack_lookup[15][32] =
{
	{ // ARRSPEC_NONE = 0
		(Register []){}, (Register []){}, (Register []){}, (Register []){},
		(Register []){}, (Register []){}, (Register []){}, (Register []){},
		(Register []){}, (Register []){}, (Register []){}, (Register []){},
		(Register []){}, (Register []){}, (Register []){}, (Register []){},
		(Register []){}, (Register []){}, (Register []){}, (Register []){},
		(Register []){}, (Register []){}, (Register []){}, (Register []){},
		(Register []){}, (Register []){}, (Register []){}, (Register []){},
		(Register []){}, (Register []){}, (Register []){}, (Register []){}
	},
	{ // ARRSPEC_FULL = 1
		(Register []){REG_V0},  (Register []){REG_V1},  (Register []){REG_V2},  (Register []){REG_V3},
		(Register []){REG_V4},  (Register []){REG_V5},  (Register []){REG_V6},  (Register []){REG_V7},
		(Register []){REG_V8},  (Register []){REG_V9},  (Register []){REG_V10}, (Register []){REG_V11},
		(Register []){REG_V12}, (Register []){REG_V13}, (Register []){REG_V14}, (Register []){REG_V15},
		(Register []){REG_V16}, (Register []){REG_V17}, (Register []){REG_V18}, (Register []){REG_V19},
		(Register []){REG_V20}, (Register []){REG_V21}, (Register []){REG_V22}, (Register []){REG_V23},
		(Register []){REG_V24}, (Register []){REG_V25}, (Register []){REG_V26}, (Register []){REG_V27},
		(Register []){REG_V28}, (Register []){REG_V29}, (Register []){REG_V30}, (Register []){REG_V31}
	},
	{ // ARRSPEC_2DOUBLES = 2
		(Register []){REG_V0_D0, REG_V0_D1}, (Register []){REG_V1_D0, REG_V1_D1},
		(Register []){REG_V2_D0, REG_V2_D1}, (Register []){REG_V3_D0, REG_V3_D1},
		(Register []){REG_V4_D0, REG_V4_D1}, (Register []){REG_V5_D0, REG_V5_D1},
		(Register []){REG_V6_D0, REG_V6_D1}, (Register []){REG_V7_D0, REG_V7_D1},
		(Register []){REG_V8_D0, REG_V8_D1}, (Register []){REG_V9_D0, REG_V9_D1},
		(Register []){REG_V10_D0, REG_V10_D1}, (Register []){REG_V11_D0, REG_V11_D1},
		(Register []){REG_V12_D0, REG_V12_D1}, (Register []){REG_V13_D0, REG_V13_D1},
		(Register []){REG_V14_D0, REG_V14_D1}, (Register []){REG_V15_D0, REG_V15_D1},
		(Register []){REG_V16_D0, REG_V16_D1}, (Register []){REG_V17_D0, REG_V17_D1},
		(Register []){REG_V18_D0, REG_V18_D1}, (Register []){REG_V19_D0, REG_V19_D1},
		(Register []){REG_V20_D0, REG_V20_D1}, (Register []){REG_V21_D0, REG_V21_D1},
		(Register []){REG_V22_D0, REG_V22_D1}, (Register []){REG_V23_D0, REG_V23_D1},
		(Register []){REG_V24_D0, REG_V24_D1}, (Register []){REG_V25_D0, REG_V25_D1},
		(Register []){REG_V26_D0, REG_V26_D1}, (Register []){REG_V27_D0, REG_V27_D1},
		(Register []){REG_V28_D0, REG_V28_D1}, (Register []){REG_V29_D0, REG_V29_D1},
		(Register []){REG_V30_D0, REG_V30_D1}, (Register []){REG_V31_D0, REG_V31_D1}
	},
	{ // ARRSPEC_4SINGLES = 3
		(Register []){REG_V0_S0, REG_V0_S1, REG_V0_S2, REG_V0_S3}, (Register []){REG_V1_S0, REG_V1_S1, REG_V1_S2, REG_V1_S3},
		(Register []){REG_V2_S0, REG_V2_S1, REG_V2_S2, REG_V2_S3}, (Register []){REG_V3_S0, REG_V3_S1, REG_V3_S2, REG_V3_S3},
		(Register []){REG_V4_S0, REG_V4_S1, REG_V4_S2, REG_V4_S3}, (Register []){REG_V5_S0, REG_V5_S1, REG_V5_S2, REG_V5_S3},
		(Register []){REG_V6_S0, REG_V6_S1, REG_V6_S2, REG_V6_S3}, (Register []){REG_V7_S0, REG_V7_S1, REG_V7_S2, REG_V7_S3},
		(Register []){REG_V8_S0, REG_V8_S1, REG_V8_S2, REG_V8_S3}, (Register []){REG_V9_S0, REG_V9_S1, REG_V9_S2, REG_V9_S3},
		(Register []){REG_V10_S0, REG_V10_S1, REG_V10_S2, REG_V10_S3}, (Register []){REG_V11_S0, REG_V11_S1, REG_V11_S2, REG_V11_S3},
		(Register []){REG_V12_S0, REG_V12_S1, REG_V12_S2, REG_V12_S3}, (Register []){REG_V13_S0, REG_V13_S1, REG_V13_S2, REG_V13_S3},
		(Register []){REG_V14_S0, REG_V14_S1, REG_V14_S2, REG_V14_S3}, (Register []){REG_V15_S0, REG_V15_S1, REG_V15_S2, REG_V15_S3},
		(Register []){REG_V16_S0, REG_V16_S1, REG_V16_S2, REG_V16_S3}, (Register []){REG_V17_S0, REG_V17_S1, REG_V17_S2, REG_V17_S3},
		(Register []){REG_V18_S0, REG_V18_S1, REG_V18_S2, REG_V18_S3}, (Register []){REG_V19_S0, REG_V19_S1, REG_V19_S2, REG_V19_S3},
		(Register []){REG_V20_S0, REG_V20_S1, REG_V20_S2, REG_V20_S3}, (Register []){REG_V21_S0, REG_V21_S1, REG_V21_S2, REG_V21_S3},
		(Register []){REG_V22_S0, REG_V22_S1, REG_V22_S2, REG_V22_S3}, (Register []){REG_V23_S0, REG_V23_S1, REG_V23_S2, REG_V23_S3},
		(Register []){REG_V24_S0, REG_V24_S1, REG_V24_S2, REG_V24_S3}, (Register []){REG_V25_S0, REG_V25_S1, REG_V25_S2, REG_V25_S3},
		(Register []){REG_V26_S0, REG_V26_S1, REG_V26_S2, REG_V26_S3}, (Register []){REG_V27_S0, REG_V27_S1, REG_V27_S2, REG_V27_S3},
		(Register []){REG_V28_S0, REG_V28_S1, REG_V28_S2, REG_V28_S3}, (Register []){REG_V29_S0, REG_V29_S1, REG_V29_S2, REG_V29_S3},
		(Register []){REG_V30_S0, REG_V30_S1, REG_V30_S2, REG_V30_S3}, (Register []){REG_V31_S0, REG_V31_S1, REG_V31_S2, REG_V31_S3}
	},
	{ // ARRSPEC_8HALVES = 4
		(Register []){REG_V0_H0, REG_V0_H1, REG_V0_H2, REG_V0_H3, REG_V0_H4, REG_V0_H5, REG_V0_H6, REG_V0_H7},
		(Register []){REG_V1_H0, REG_V1_H1, REG_V1_H2, REG_V1_H3, REG_V1_H4, REG_V1_H5, REG_V1_H6, REG_V1_H7},
		(Register []){REG_V2_H0, REG_V2_H1, REG_V2_H2, REG_V2_H3, REG_V2_H4, REG_V2_H5, REG_V2_H6, REG_V2_H7},
		(Register []){REG_V3_H0, REG_V3_H1, REG_V3_H2, REG_V3_H3, REG_V3_H4, REG_V3_H5, REG_V3_H6, REG_V3_H7},
		(Register []){REG_V4_H0, REG_V4_H1, REG_V4_H2, REG_V4_H3, REG_V4_H4, REG_V4_H5, REG_V4_H6, REG_V4_H7},
		(Register []){REG_V5_H0, REG_V5_H1, REG_V5_H2, REG_V5_H3, REG_V5_H4, REG_V5_H5, REG_V5_H6, REG_V5_H7},
		(Register []){REG_V6_H0, REG_V6_H1, REG_V6_H2, REG_V6_H3, REG_V6_H4, REG_V6_H5, REG_V6_H6, REG_V6_H7},
		(Register []){REG_V7_H0, REG_V7_H1, REG_V7_H2, REG_V7_H3, REG_V7_H4, REG_V7_H5, REG_V7_H6, REG_V7_H7},
		(Register []){REG_V8_H0, REG_V8_H1, REG_V8_H2, REG_V8_H3, REG_V8_H4, REG_V8_H5, REG_V8_H6, REG_V8_H7},
		(Register []){REG_V9_H0, REG_V9_H1, REG_V9_H2, REG_V9_H3, REG_V9_H4, REG_V9_H5, REG_V9_H6, REG_V9_H7},
		(Register []){REG_V10_H0, REG_V10_H1, REG_V10_H2, REG_V10_H3, REG_V10_H4, REG_V10_H5, REG_V10_H6, REG_V10_H7},
		(Register []){REG_V11_H0, REG_V11_H1, REG_V11_H2, REG_V11_H3, REG_V11_H4, REG_V11_H5, REG_V11_H6, REG_V11_H7},
		(Register []){REG_V12_H0, REG_V12_H1, REG_V12_H2, REG_V12_H3, REG_V12_H4, REG_V12_H5, REG_V12_H6, REG_V12_H7},
		(Register []){REG_V13_H0, REG_V13_H1, REG_V13_H2, REG_V13_H3, REG_V13_H4, REG_V13_H5, REG_V13_H6, REG_V13_H7},
		(Register []){REG_V14_H0, REG_V14_H1, REG_V14_H2, REG_V14_H3, REG_V14_H4, REG_V14_H5, REG_V14_H6, REG_V14_H7},
		(Register []){REG_V15_H0, REG_V15_H1, REG_V15_H2, REG_V15_H3, REG_V15_H4, REG_V15_H5, REG_V15_H6, REG_V15_H7},
		(Register []){REG_V16_H0, REG_V16_H1, REG_V16_H2, REG_V16_H3, REG_V16_H4, REG_V16_H5, REG_V16_H6, REG_V16_H7},
		(Register []){REG_V17_H0, REG_V17_H1, REG_V17_H2, REG_V17_H3, REG_V17_H4, REG_V17_H5, REG_V17_H6, REG_V17_H7},
		(Register []){REG_V18_H0, REG_V18_H1, REG_V18_H2, REG_V18_H3, REG_V18_H4, REG_V18_H5, REG_V18_H6, REG_V18_H7},
		(Register []){REG_V19_H0, REG_V19_H1, REG_V19_H2, REG_V19_H3, REG_V19_H4, REG_V19_H5, REG_V19_H6, REG_V19_H7},
		(Register []){REG_V20_H0, REG_V20_H1, REG_V20_H2, REG_V20_H3, REG_V20_H4, REG_V20_H5, REG_V20_H6, REG_V20_H7},
		(Register []){REG_V21_H0, REG_V21_H1, REG_V21_H2, REG_V21_H3, REG_V21_H4, REG_V21_H5, REG_V21_H6, REG_V21_H7},
		(Register []){REG_V22_H0, REG_V22_H1, REG_V22_H2, REG_V22_H3, REG_V22_H4, REG_V22_H5, REG_V22_H6, REG_V22_H7},
		(Register []){REG_V23_H0, REG_V23_H1, REG_V23_H2, REG_V23_H3, REG_V23_H4, REG_V23_H5, REG_V23_H6, REG_V23_H7},
		(Register []){REG_V24_H0, REG_V24_H1, REG_V24_H2, REG_V24_H3, REG_V24_H4, REG_V24_H5, REG_V24_H6, REG_V24_H7},
		(Register []){REG_V25_H0, REG_V25_H1, REG_V25_H2, REG_V25_H3, REG_V25_H4, REG_V25_H5, REG_V25_H6, REG_V25_H7},
		(Register []){REG_V26_H0, REG_V26_H1, REG_V26_H2, REG_V26_H3, REG_V26_H4, REG_V26_H5, REG_V26_H6, REG_V26_H7},
		(Register []){REG_V27_H0, REG_V27_H1, REG_V27_H2, REG_V27_H3, REG_V27_H4, REG_V27_H5, REG_V27_H6, REG_V27_H7},
		(Register []){REG_V28_H0, REG_V28_H1, REG_V28_H2, REG_V28_H3, REG_V28_H4, REG_V28_H5, REG_V28_H6, REG_V28_H7},
		(Register []){REG_V29_H0, REG_V29_H1, REG_V29_H2, REG_V29_H3, REG_V29_H4, REG_V29_H5, REG_V29_H6, REG_V29_H7},
		(Register []){REG_V30_H0, REG_V30_H1, REG_V30_H2, REG_V30_H3, REG_V30_H4, REG_V30_H5, REG_V30_H6, REG_V30_H7},
		(Register []){REG_V31_H0, REG_V31_H1, REG_V31_H2, REG_V31_H3, REG_V31_H4, REG_V31_H5, REG_V31_H6, REG_V31_H7}
	},
	{ // ARRSPEC_16BYTES = 5
		(Register []){REG_V0_B0, REG_V0_B1, REG_V0_B2, REG_V0_B3, REG_V0_B4, REG_V0_B5, REG_V0_B6, REG_V0_B7,
		  REG_V0_B8, REG_V0_B9, REG_V0_B10, REG_V0_B11, REG_V0_B12, REG_V0_B13, REG_V0_B14, REG_V0_B15},
		(Register []){REG_V1_B0, REG_V1_B1, REG_V1_B2, REG_V1_B3, REG_V1_B4, REG_V1_B5, REG_V1_B6, REG_V1_B7,
		  REG_V1_B8, REG_V1_B9, REG_V1_B10, REG_V1_B11, REG_V1_B12, REG_V1_B13, REG_V1_B14, REG_V1_B15},
		(Register []){REG_V2_B0, REG_V2_B1, REG_V2_B2, REG_V2_B3, REG_V2_B4, REG_V2_B5, REG_V2_B6, REG_V2_B7,
		  REG_V2_B8, REG_V2_B9, REG_V2_B10, REG_V2_B11, REG_V2_B12, REG_V2_B13, REG_V2_B14, REG_V2_B15},
		(Register []){REG_V3_B0, REG_V3_B1, REG_V3_B2, REG_V3_B3, REG_V3_B4, REG_V3_B5, REG_V3_B6, REG_V3_B7,
		  REG_V3_B8, REG_V3_B9, REG_V3_B10, REG_V3_B11, REG_V3_B12, REG_V3_B13, REG_V3_B14, REG_V3_B15},
		(Register []){REG_V4_B0, REG_V4_B1, REG_V4_B2, REG_V4_B3, REG_V4_B4, REG_V4_B5, REG_V4_B6, REG_V4_B7,
		  REG_V4_B8, REG_V4_B9, REG_V4_B10, REG_V4_B11, REG_V4_B12, REG_V4_B13, REG_V4_B14, REG_V4_B15},
		(Register []){REG_V5_B0, REG_V5_B1, REG_V5_B2, REG_V5_B3, REG_V5_B4, REG_V5_B5, REG_V5_B6, REG_V5_B7,
		  REG_V5_B8, REG_V5_B9, REG_V5_B10, REG_V5_B11, REG_V5_B12, REG_V5_B13, REG_V5_B14, REG_V5_B15},
		(Register []){REG_V6_B0, REG_V6_B1, REG_V6_B2, REG_V6_B3, REG_V6_B4, REG_V6_B5, REG_V6_B6, REG_V6_B7,
		  REG_V6_B8, REG_V6_B9, REG_V6_B10, REG_V6_B11, REG_V6_B12, REG_V6_B13, REG_V6_B14, REG_V6_B15},
		(Register []){REG_V7_B0, REG_V7_B1, REG_V7_B2, REG_V7_B3, REG_V7_B4, REG_V7_B5, REG_V7_B6, REG_V7_B7,
		  REG_V7_B8, REG_V7_B9, REG_V7_B10, REG_V7_B11, REG_V7_B12, REG_V7_B13, REG_V7_B14, REG_V7_B15},
		(Register []){REG_V8_B0, REG_V8_B1, REG_V8_B2, REG_V8_B3, REG_V8_B4, REG_V8_B5, REG_V8_B6, REG_V8_B7,
		  REG_V8_B8, REG_V8_B9, REG_V8_B10, REG_V8_B11, REG_V8_B12, REG_V8_B13, REG_V8_B14, REG_V8_B15},
		(Register []){REG_V9_B0, REG_V9_B1, REG_V9_B2, REG_V9_B3, REG_V9_B4, REG_V9_B5, REG_V9_B6, REG_V9_B7,
		  REG_V9_B8, REG_V9_B9, REG_V9_B10, REG_V9_B11, REG_V9_B12, REG_V9_B13, REG_V9_B14, REG_V9_B15},
		(Register []){REG_V10_B0, REG_V10_B1, REG_V10_B2, REG_V10_B3, REG_V10_B4, REG_V10_B5, REG_V10_B6, REG_V10_B7,
		  REG_V10_B8, REG_V10_B9, REG_V10_B10, REG_V10_B11, REG_V10_B12, REG_V10_B13, REG_V10_B14, REG_V10_B15},
		(Register []){REG_V11_B0, REG_V11_B1, REG_V11_B2, REG_V11_B3, REG_V11_B4, REG_V11_B5, REG_V11_B6, REG_V11_B7,
		  REG_V11_B8, REG_V11_B9, REG_V11_B10, REG_V11_B11, REG_V11_B12, REG_V11_B13, REG_V11_B14, REG_V11_B15},
		(Register []){REG_V12_B0, REG_V12_B1, REG_V12_B2, REG_V12_B3, REG_V12_B4, REG_V12_B5, REG_V12_B6, REG_V12_B7,
		  REG_V12_B8, REG_V12_B9, REG_V12_B10, REG_V12_B11, REG_V12_B12, REG_V12_B13, REG_V12_B14, REG_V12_B15},
		(Register []){REG_V13_B0, REG_V13_B1, REG_V13_B2, REG_V13_B3, REG_V13_B4, REG_V13_B5, REG_V13_B6, REG_V13_B7,
		  REG_V13_B8, REG_V13_B9, REG_V13_B10, REG_V13_B11, REG_V13_B12, REG_V13_B13, REG_V13_B14, REG_V13_B15},
		(Register []){REG_V14_B0, REG_V14_B1, REG_V14_B2, REG_V14_B3, REG_V14_B4, REG_V14_B5, REG_V14_B6, REG_V14_B7,
		  REG_V14_B8, REG_V14_B9, REG_V14_B10, REG_V14_B11, REG_V14_B12, REG_V14_B13, REG_V14_B14, REG_V14_B15},
		(Register []){REG_V15_B0, REG_V15_B1, REG_V15_B2, REG_V15_B3, REG_V15_B4, REG_V15_B5, REG_V15_B6, REG_V15_B7,
		  REG_V15_B8, REG_V15_B9, REG_V15_B10, REG_V15_B11, REG_V15_B12, REG_V15_B13, REG_V15_B14, REG_V15_B15},
		(Register []){REG_V16_B0, REG_V16_B1, REG_V16_B2, REG_V16_B3, REG_V16_B4, REG_V16_B5, REG_V16_B6, REG_V16_B7,
		  REG_V16_B8, REG_V16_B9, REG_V16_B10, REG_V16_B11, REG_V16_B12, REG_V16_B13, REG_V16_B14, REG_V16_B15},
		(Register []){REG_V17_B0, REG_V17_B1, REG_V17_B2, REG_V17_B3, REG_V17_B4, REG_V17_B5, REG_V17_B6, REG_V17_B7,
		  REG_V17_B8, REG_V17_B9, REG_V17_B10, REG_V17_B11, REG_V17_B12, REG_V17_B13, REG_V17_B14, REG_V17_B15},
		(Register []){REG_V18_B0, REG_V18_B1, REG_V18_B2, REG_V18_B3, REG_V18_B4, REG_V18_B5, REG_V18_B6, REG_V18_B7,
		  REG_V18_B8, REG_V18_B9, REG_V18_B10, REG_V18_B11, REG_V18_B12, REG_V18_B13, REG_V18_B14, REG_V18_B15},
		(Register []){REG_V19_B0, REG_V19_B1, REG_V19_B2, REG_V19_B3, REG_V19_B4, REG_V19_B5, REG_V19_B6, REG_V19_B7,
		  REG_V19_B8, REG_V19_B9, REG_V19_B10, REG_V19_B11, REG_V19_B12, REG_V19_B13, REG_V19_B14, REG_V19_B15},
		(Register []){REG_V20_B0, REG_V20_B1, REG_V20_B2, REG_V20_B3, REG_V20_B4, REG_V20_B5, REG_V20_B6, REG_V20_B7,
		  REG_V20_B8, REG_V20_B9, REG_V20_B10, REG_V20_B11, REG_V20_B12, REG_V20_B13, REG_V20_B14, REG_V20_B15},
		(Register []){REG_V21_B0, REG_V21_B1, REG_V21_B2, REG_V21_B3, REG_V21_B4, REG_V21_B5, REG_V21_B6, REG_V21_B7,
		  REG_V21_B8, REG_V21_B9, REG_V21_B10, REG_V21_B11, REG_V21_B12, REG_V21_B13, REG_V21_B14, REG_V21_B15},
		(Register []){REG_V22_B0, REG_V22_B1, REG_V22_B2, REG_V22_B3, REG_V22_B4, REG_V22_B5, REG_V22_B6, REG_V22_B7,
		  REG_V22_B8, REG_V22_B9, REG_V22_B10, REG_V22_B11, REG_V22_B12, REG_V22_B13, REG_V22_B14, REG_V22_B15},
		(Register []){REG_V23_B0, REG_V23_B1, REG_V23_B2, REG_V23_B3, REG_V23_B4, REG_V23_B5, REG_V23_B6, REG_V23_B7,
		  REG_V23_B8, REG_V23_B9, REG_V23_B10, REG_V23_B11, REG_V23_B12, REG_V23_B13, REG_V23_B14, REG_V23_B15},
		(Register []){REG_V24_B0, REG_V24_B1, REG_V24_B2, REG_V24_B3, REG_V24_B4, REG_V24_B5, REG_V24_B6, REG_V24_B7,
		  REG_V24_B8, REG_V24_B9, REG_V24_B10, REG_V24_B11, REG_V24_B12, REG_V24_B13, REG_V24_B14, REG_V24_B15},
		(Register []){REG_V25_B0, REG_V25_B1, REG_V25_B2, REG_V25_B3, REG_V25_B4, REG_V25_B5, REG_V25_B6, REG_V25_B7,
		  REG_V25_B8, REG_V25_B9, REG_V25_B10, REG_V25_B11, REG_V25_B12, REG_V25_B13, REG_V25_B14, REG_V25_B15},
		(Register []){REG_V26_B0, REG_V26_B1, REG_V26_B2, REG_V26_B3, REG_V26_B4, REG_V26_B5, REG_V26_B6, REG_V26_B7,
		  REG_V26_B8, REG_V26_B9, REG_V26_B10, REG_V26_B11, REG_V26_B12, REG_V26_B13, REG_V26_B14, REG_V26_B15},
		(Register []){REG_V27_B0, REG_V27_B1, REG_V27_B2, REG_V27_B3, REG_V27_B4, REG_V27_B5, REG_V27_B6, REG_V27_B7,
		  REG_V27_B8, REG_V27_B9, REG_V27_B10, REG_V27_B11, REG_V27_B12, REG_V27_B13, REG_V27_B14, REG_V27_B15},
		(Register []){REG_V28_B0, REG_V28_B1, REG_V28_B2, REG_V28_B3, REG_V28_B4, REG_V28_B5, REG_V28_B6, REG_V28_B7,
		  REG_V28_B8, REG_V28_B9, REG_V28_B10, REG_V28_B11, REG_V28_B12, REG_V28_B13, REG_V28_B14, REG_V28_B15},
		(Register []){REG_V29_B0, REG_V29_B1, REG_V29_B2, REG_V29_B3, REG_V29_B4, REG_V29_B5, REG_V29_B6, REG_V29_B7,
		  REG_V29_B8, REG_V29_B9, REG_V29_B10, REG_V29_B11, REG_V29_B12, REG_V29_B13, REG_V29_B14, REG_V29_B15},
		(Register []){REG_V30_B0, REG_V30_B1, REG_V30_B2, REG_V30_B3, REG_V30_B4, REG_V30_B5, REG_V30_B6, REG_V30_B7,
		  REG_V30_B8, REG_V30_B9, REG_V30_B10, REG_V30_B11, REG_V30_B12, REG_V30_B13, REG_V30_B14, REG_V30_B15},
		(Register []){REG_V31_B0, REG_V31_B1, REG_V31_B2, REG_V31_B3, REG_V31_B4, REG_V31_B5, REG_V31_B6, REG_V31_B7,
		  REG_V31_B8, REG_V31_B9, REG_V31_B10, REG_V31_B11, REG_V31_B12, REG_V31_B13, REG_V31_B14, REG_V31_B15},
	},
	{// ARRSPEC_1DOUBLE = 6
		(Register []){REG_V0_D0}, (Register []){REG_V1_D0}, (Register []){REG_V2_D0}, (Register []){REG_V3_D0},
		(Register []){REG_V4_D0}, (Register []){REG_V5_D0}, (Register []){REG_V6_D0}, (Register []){REG_V7_D0},
		(Register []){REG_V8_D0}, (Register []){REG_V9_D0}, (Register []){REG_V10_D0}, (Register []){REG_V11_D0},
		(Register []){REG_V12_D0}, (Register []){REG_V13_D0}, (Register []){REG_V14_D0}, (Register []){REG_V15_D0},
		(Register []){REG_V16_D0}, (Register []){REG_V17_D0}, (Register []){REG_V18_D0}, (Register []){REG_V19_D0},
		(Register []){REG_V20_D0}, (Register []){REG_V21_D0}, (Register []){REG_V22_D0}, (Register []){REG_V23_D0},
		(Register []){REG_V24_D0}, (Register []){REG_V25_D0}, (Register []){REG_V26_D0}, (Register []){REG_V27_D0},
		(Register []){REG_V28_D0}, (Register []){REG_V29_D0}, (Register []){REG_V30_D0}, (Register []){REG_V31_D0}
	},
	{// ARRSPEC_2SINGLES = 7
		(Register []){REG_V0_S0, REG_V0_S1}, (Register []){REG_V1_S0, REG_V1_S1},
		(Register []){REG_V2_S0, REG_V2_S1}, (Register []){REG_V3_S0, REG_V3_S1},
		(Register []){REG_V4_S0, REG_V4_S1}, (Register []){REG_V5_S0, REG_V5_S1},
		(Register []){REG_V6_S0, REG_V6_S1}, (Register []){REG_V7_S0, REG_V7_S1},
		(Register []){REG_V8_S0, REG_V8_S1}, (Register []){REG_V9_S0, REG_V9_S1},
		(Register []){REG_V10_S0, REG_V10_S1}, (Register []){REG_V11_S0, REG_V11_S1},
		(Register []){REG_V12_S0, REG_V12_S1}, (Register []){REG_V13_S0, REG_V13_S1},
		(Register []){REG_V14_S0, REG_V14_S1}, (Register []){REG_V15_S0, REG_V15_S1},
		(Register []){REG_V16_S0, REG_V16_S1}, (Register []){REG_V17_S0, REG_V17_S1},
		(Register []){REG_V18_S0, REG_V18_S1}, (Register []){REG_V19_S0, REG_V19_S1},
		(Register []){REG_V20_S0, REG_V20_S1}, (Register []){REG_V21_S0, REG_V21_S1},
		(Register []){REG_V22_S0, REG_V22_S1}, (Register []){REG_V23_S0, REG_V23_S1},
		(Register []){REG_V24_S0, REG_V24_S1}, (Register []){REG_V25_S0, REG_V25_S1},
		(Register []){REG_V26_S0, REG_V26_S1}, (Register []){REG_V27_S0, REG_V27_S1},
		(Register []){REG_V28_S0, REG_V28_S1}, (Register []){REG_V29_S0, REG_V29_S1},
		(Register []){REG_V30_S0, REG_V30_S1}, (Register []){REG_V31_S0, REG_V31_S1}
	},
	{// ARRSPEC_4HALVES = 8
		(Register []){REG_V0_H0, REG_V0_H1, REG_V0_H2, REG_V0_H3}, (Register []){REG_V1_H0, REG_V1_H1, REG_V1_H2, REG_V1_H3},
		(Register []){REG_V2_H0, REG_V2_H1, REG_V2_H2, REG_V2_H3}, (Register []){REG_V3_H0, REG_V3_H1, REG_V3_H2, REG_V3_H3},
		(Register []){REG_V4_H0, REG_V4_H1, REG_V4_H2, REG_V4_H3}, (Register []){REG_V5_H0, REG_V5_H1, REG_V5_H2, REG_V5_H3},
		(Register []){REG_V6_H0, REG_V6_H1, REG_V6_H2, REG_V6_H3}, (Register []){REG_V7_H0, REG_V7_H1, REG_V7_H2, REG_V7_H3},
		(Register []){REG_V8_H0, REG_V8_H1, REG_V8_H2, REG_V8_H3}, (Register []){REG_V9_H0, REG_V9_H1, REG_V9_H2, REG_V9_H3},
		(Register []){REG_V10_H0, REG_V10_H1, REG_V10_H2, REG_V10_H3}, (Register []){REG_V11_H0, REG_V11_H1, REG_V11_H2, REG_V11_H3},
		(Register []){REG_V12_H0, REG_V12_H1, REG_V12_H2, REG_V12_H3}, (Register []){REG_V13_H0, REG_V13_H1, REG_V13_H2, REG_V13_H3},
		(Register []){REG_V14_H0, REG_V14_H1, REG_V14_H2, REG_V14_H3}, (Register []){REG_V15_H0, REG_V15_H1, REG_V15_H2, REG_V15_H3},
		(Register []){REG_V16_H0, REG_V16_H1, REG_V16_H2, REG_V16_H3}, (Register []){REG_V17_H0, REG_V17_H1, REG_V17_H2, REG_V17_H3},
		(Register []){REG_V18_H0, REG_V18_H1, REG_V18_H2, REG_V18_H3}, (Register []){REG_V19_H0, REG_V19_H1, REG_V19_H2, REG_V19_H3},
		(Register []){REG_V20_H0, REG_V20_H1, REG_V20_H2, REG_V20_H3}, (Register []){REG_V21_H0, REG_V21_H1, REG_V21_H2, REG_V21_H3},
		(Register []){REG_V22_H0, REG_V22_H1, REG_V22_H2, REG_V22_H3}, (Register []){REG_V23_H0, REG_V23_H1, REG_V23_H2, REG_V23_H3},
		(Register []){REG_V24_H0, REG_V24_H1, REG_V24_H2, REG_V24_H3}, (Register []){REG_V25_H0, REG_V25_H1, REG_V25_H2, REG_V25_H3},
		(Register []){REG_V26_H0, REG_V26_H1, REG_V26_H2, REG_V26_H3}, (Register []){REG_V27_H0, REG_V27_H1, REG_V27_H2, REG_V27_H3},
		(Register []){REG_V28_H0, REG_V28_H1, REG_V28_H2, REG_V28_H3}, (Register []){REG_V29_H0, REG_V29_H1, REG_V29_H2, REG_V29_H3},
		(Register []){REG_V30_H0, REG_V30_H1, REG_V30_H2, REG_V30_H3}, (Register []){REG_V31_H0, REG_V31_H1, REG_V31_H2, REG_V31_H3}
	},
	{// ARRSPEC_8BYTES = 9
		(Register []){REG_V0_B0, REG_V0_B1, REG_V0_B2, REG_V0_B3, REG_V0_B4, REG_V0_B5, REG_V0_B6, REG_V0_B7},
		(Register []){REG_V1_B0, REG_V1_B1, REG_V1_B2, REG_V1_B3, REG_V1_B4, REG_V1_B5, REG_V1_B6, REG_V1_B7},
		(Register []){REG_V2_B0, REG_V2_B1, REG_V2_B2, REG_V2_B3, REG_V2_B4, REG_V2_B5, REG_V2_B6, REG_V2_B7},
		(Register []){REG_V3_B0, REG_V3_B1, REG_V3_B2, REG_V3_B3, REG_V3_B4, REG_V3_B5, REG_V3_B6, REG_V3_B7},
		(Register []){REG_V4_B0, REG_V4_B1, REG_V4_B2, REG_V4_B3, REG_V4_B4, REG_V4_B5, REG_V4_B6, REG_V4_B7},
		(Register []){REG_V5_B0, REG_V5_B1, REG_V5_B2, REG_V5_B3, REG_V5_B4, REG_V5_B5, REG_V5_B6, REG_V5_B7},
		(Register []){REG_V6_B0, REG_V6_B1, REG_V6_B2, REG_V6_B3, REG_V6_B4, REG_V6_B5, REG_V6_B6, REG_V6_B7},
		(Register []){REG_V7_B0, REG_V7_B1, REG_V7_B2, REG_V7_B3, REG_V7_B4, REG_V7_B5, REG_V7_B6, REG_V7_B7},
		(Register []){REG_V8_B0, REG_V8_B1, REG_V8_B2, REG_V8_B3, REG_V8_B4, REG_V8_B5, REG_V8_B6, REG_V8_B7},
		(Register []){REG_V9_B0, REG_V9_B1, REG_V9_B2, REG_V9_B3, REG_V9_B4, REG_V9_B5, REG_V9_B6, REG_V9_B7},
		(Register []){REG_V10_B0, REG_V10_B1, REG_V10_B2, REG_V10_B3, REG_V10_B4, REG_V10_B5, REG_V10_B6, REG_V10_B7},
		(Register []){REG_V11_B0, REG_V11_B1, REG_V11_B2, REG_V11_B3, REG_V11_B4, REG_V11_B5, REG_V11_B6, REG_V11_B7},
		(Register []){REG_V12_B0, REG_V12_B1, REG_V12_B2, REG_V12_B3, REG_V12_B4, REG_V12_B5, REG_V12_B6, REG_V12_B7},
		(Register []){REG_V13_B0, REG_V13_B1, REG_V13_B2, REG_V13_B3, REG_V13_B4, REG_V13_B5, REG_V13_B6, REG_V13_B7},
		(Register []){REG_V14_B0, REG_V14_B1, REG_V14_B2, REG_V14_B3, REG_V14_B4, REG_V14_B5, REG_V14_B6, REG_V14_B7},
		(Register []){REG_V15_B0, REG_V15_B1, REG_V15_B2, REG_V15_B3, REG_V15_B4, REG_V15_B5, REG_V15_B6, REG_V15_B7},
		(Register []){REG_V16_B0, REG_V16_B1, REG_V16_B2, REG_V16_B3, REG_V16_B4, REG_V16_B5, REG_V16_B6, REG_V16_B7},
		(Register []){REG_V17_B0, REG_V17_B1, REG_V17_B2, REG_V17_B3, REG_V17_B4, REG_V17_B5, REG_V17_B6, REG_V17_B7},
		(Register []){REG_V18_B0, REG_V18_B1, REG_V18_B2, REG_V18_B3, REG_V18_B4, REG_V18_B5, REG_V18_B6, REG_V18_B7},
		(Register []){REG_V19_B0, REG_V19_B1, REG_V19_B2, REG_V19_B3, REG_V19_B4, REG_V19_B5, REG_V19_B6, REG_V19_B7},
		(Register []){REG_V20_B0, REG_V20_B1, REG_V20_B2, REG_V20_B3, REG_V20_B4, REG_V20_B5, REG_V20_B6, REG_V20_B7},
		(Register []){REG_V21_B0, REG_V21_B1, REG_V21_B2, REG_V21_B3, REG_V21_B4, REG_V21_B5, REG_V21_B6, REG_V21_B7},
		(Register []){REG_V22_B0, REG_V22_B1, REG_V22_B2, REG_V22_B3, REG_V22_B4, REG_V22_B5, REG_V22_B6, REG_V22_B7},
		(Register []){REG_V23_B0, REG_V23_B1, REG_V23_B2, REG_V23_B3, REG_V23_B4, REG_V23_B5, REG_V23_B6, REG_V23_B7},
		(Register []){REG_V24_B0, REG_V24_B1, REG_V24_B2, REG_V24_B3, REG_V24_B4, REG_V24_B5, REG_V24_B6, REG_V24_B7},
		(Register []){REG_V25_B0, REG_V25_B1, REG_V25_B2, REG_V25_B3, REG_V25_B4, REG_V25_B5, REG_V25_B6, REG_V25_B7},
		(Register []){REG_V26_B0, REG_V26_B1, REG_V26_B2, REG_V26_B3, REG_V26_B4, REG_V26_B5, REG_V26_B6, REG_V26_B7},
		(Register []){REG_V27_B0, REG_V27_B1, REG_V27_B2, REG_V27_B3, REG_V27_B4, REG_V27_B5, REG_V27_B6, REG_V27_B7},
		(Register []){REG_V28_B0, REG_V28_B1, REG_V28_B2, REG_V28_B3, REG_V28_B4, REG_V28_B5, REG_V28_B6, REG_V28_B7},
		(Register []){REG_V29_B0, REG_V29_B1, REG_V29_B2, REG_V29_B3, REG_V29_B4, REG_V29_B5, REG_V29_B6, REG_V29_B7},
		(Register []){REG_V30_B0, REG_V30_B1, REG_V30_B2, REG_V30_B3, REG_V30_B4, REG_V30_B5, REG_V30_B6, REG_V30_B7},
		(Register []){REG_V31_B0, REG_V31_B1, REG_V31_B2, REG_V31_B3, REG_V31_B4, REG_V31_B5, REG_V31_B6, REG_V31_B7},
	},
	{// ARRSPEC_1SINGLE = 10
		(Register []){REG_V0_S0}, (Register []){REG_V1_S0}, (Register []){REG_V2_S0}, (Register []){REG_V3_S0},
		(Register []){REG_V4_S0}, (Register []){REG_V5_S0}, (Register []){REG_V6_S0}, (Register []){REG_V7_S0},
		(Register []){REG_V8_S0}, (Register []){REG_V9_S0}, (Register []){REG_V10_S0}, (Register []){REG_V11_S0},
		(Register []){REG_V12_S0}, (Register []){REG_V13_S0}, (Register []){REG_V14_S0}, (Register []){REG_V15_S0},
		(Register []){REG_V16_S0}, (Register []){REG_V17_S0}, (Register []){REG_V18_S0}, (Register []){REG_V19_S0},
		(Register []){REG_V20_S0}, (Register []){REG_V21_S0}, (Register []){REG_V22_S0}, (Register []){REG_V23_S0}
	},
	{// ARRSPEC_2HALVES = 11
		(Register []){REG_V0_H0, REG_V0_H1}, (Register []){REG_V1_H0, REG_V1_H1},
		(Register []){REG_V2_H0, REG_V2_H1}, (Register []){REG_V3_H0, REG_V3_H1},
		(Register []){REG_V4_H0, REG_V4_H1}, (Register []){REG_V5_H0, REG_V5_H1},
		(Register []){REG_V6_H0, REG_V6_H1}, (Register []){REG_V7_H0, REG_V7_H1},
		(Register []){REG_V8_H0, REG_V8_H1}, (Register []){REG_V9_H0, REG_V9_H1},
		(Register []){REG_V10_H0, REG_V10_H1}, (Register []){REG_V11_H0, REG_V11_H1},
		(Register []){REG_V12_H0, REG_V12_H1}, (Register []){REG_V13_H0, REG_V13_H1},
		(Register []){REG_V14_H0, REG_V14_H1}, (Register []){REG_V15_H0, REG_V15_H1},
		(Register []){REG_V16_H0, REG_V16_H1}, (Register []){REG_V17_H0, REG_V17_H1},
		(Register []){REG_V18_H0, REG_V18_H1}, (Register []){REG_V19_H0, REG_V19_H1},
		(Register []){REG_V20_H0, REG_V20_H1}, (Register []){REG_V21_H0, REG_V21_H1},
		(Register []){REG_V22_H0, REG_V22_H1}, (Register []){REG_V23_H0, REG_V23_H1},
		(Register []){REG_V24_H0, REG_V24_H1}, (Register []){REG_V25_H0, REG_V25_H1},
		(Register []){REG_V26_H0, REG_V26_H1}, (Register []){REG_V27_H0, REG_V27_H1},
		(Register []){REG_V28_H0, REG_V28_H1}, (Register []){REG_V29_H0, REG_V29_H1},
		(Register []){REG_V30_H0, REG_V30_H1}, (Register []){REG_V31_H0, REG_V31_H1}
	},
	{// ARRSPEC_4BYTES = 12
		(Register []){REG_V0_B0, REG_V0_B1, REG_V0_B2, REG_V0_B3}, (Register []){REG_V1_B0, REG_V1_B1, REG_V1_B2, REG_V1_B3},
		(Register []){REG_V2_B0, REG_V2_B1, REG_V2_B2, REG_V2_B3}, (Register []){REG_V3_B0, REG_V3_B1, REG_V3_B2, REG_V3_B3},
		(Register []){REG_V4_B0, REG_V4_B1, REG_V4_B2, REG_V4_B3}, (Register []){REG_V5_B0, REG_V5_B1, REG_V5_B2, REG_V5_B3},
		(Register []){REG_V6_B0, REG_V6_B1, REG_V6_B2, REG_V6_B3}, (Register []){REG_V7_B0, REG_V7_B1, REG_V7_B2, REG_V7_B3},
		(Register []){REG_V8_B0, REG_V8_B1, REG_V8_B2, REG_V8_B3}, (Register []){REG_V9_B0, REG_V9_B1, REG_V9_B2, REG_V9_B3},
		(Register []){REG_V10_B0, REG_V10_B1, REG_V10_B2, REG_V10_B3}, (Register []){REG_V11_B0, REG_V11_B1, REG_V11_B2, REG_V11_B3},
		(Register []){REG_V12_B0, REG_V12_B1, REG_V12_B2, REG_V12_B3}, (Register []){REG_V13_B0, REG_V13_B1, REG_V13_B2, REG_V13_B3},
		(Register []){REG_V14_B0, REG_V14_B1, REG_V14_B2, REG_V14_B3}, (Register []){REG_V15_B0, REG_V15_B1, REG_V15_B2, REG_V15_B3},
		(Register []){REG_V16_B0, REG_V16_B1, REG_V16_B2, REG_V16_B3}, (Register []){REG_V17_B0, REG_V17_B1, REG_V17_B2, REG_V17_B3},
		(Register []){REG_V18_B0, REG_V18_B1, REG_V18_B2, REG_V18_B3}, (Register []){REG_V19_B0, REG_V19_B1, REG_V19_B2, REG_V19_B3},
		(Register []){REG_V20_B0, REG_V20_B1, REG_V20_B2, REG_V20_B3}, (Register []){REG_V21_B0, REG_V21_B1, REG_V21_B2, REG_V21_B3},
		(Register []){REG_V22_B0, REG_V22_B1, REG_V22_B2, REG_V22_B3}, (Register []){REG_V23_B0, REG_V23_B1, REG_V23_B2, REG_V23_B3},
		(Register []){REG_V24_B0, REG_V24_B1, REG_V24_B2, REG_V24_B3}, (Register []){REG_V25_B0, REG_V25_B1, REG_V25_B2, REG_V25_B3},
		(Register []){REG_V26_B0, REG_V26_B1, REG_V26_B2, REG_V26_B3}, (Register []){REG_V27_B0, REG_V27_B1, REG_V27_B2, REG_V27_B3},
		(Register []){REG_V28_B0, REG_V28_B1, REG_V28_B2, REG_V28_B3}, (Register []){REG_V29_B0, REG_V29_B1, REG_V29_B2, REG_V29_B3},
		(Register []){REG_V30_B0, REG_V30_B1, REG_V30_B2, REG_V30_B3}, (Register []){REG_V31_B0, REG_V31_B1, REG_V31_B2, REG_V31_B3}
	},
	{// ARRSPEC_1HALF = 13
		(Register []){REG_V0_H0}, (Register []){REG_V1_H0}, (Register []){REG_V2_H0}, (Register []){REG_V3_H0},
		(Register []){REG_V4_H0}, (Register []){REG_V5_H0}, (Register []){REG_V6_H0}, (Register []){REG_V7_H0},
		(Register []){REG_V8_H0}, (Register []){REG_V9_H0}, (Register []){REG_V10_H0}, (Register []){REG_V11_H0},
		(Register []){REG_V12_H0}, (Register []){REG_V13_H0}, (Register []){REG_V14_H0}, (Register []){REG_V15_H0},
		(Register []){REG_V16_H0}, (Register []){REG_V17_H0}, (Register []){REG_V18_H0}, (Register []){REG_V19_H0},
		(Register []){REG_V20_H0}, (Register []){REG_V21_H0}, (Register []){REG_V22_H0}, (Register []){REG_V23_H0},
		(Register []){REG_V24_H0}, (Register []){REG_V25_H0}, (Register []){REG_V26_H0}, (Register []){REG_V27_H0},
		(Register []){REG_V28_H0}, (Register []){REG_V29_H0}, (Register []){REG_V30_H0}, (Register []){REG_V31_H0}
	},
	{// ARRSPEC_1BYTE = 14
		(Register []){REG_V0_B0}, (Register []){REG_V1_B0}, (Register []){REG_V2_B0}, (Register []){REG_V3_B0},
		(Register []){REG_V4_B0}, (Register []){REG_V5_B0}, (Register []){REG_V6_B0}, (Register []){REG_V7_B0},
		(Register []){REG_V8_B0}, (Register []){REG_V9_B0}, (Register []){REG_V10_B0}, (Register []){REG_V11_B0},
		(Register []){REG_V12_B0}, (Register []){REG_V13_B0}, (Register []){REG_V14_B0}, (Register []){REG_V15_B0},
		(Register []){REG_V16_B0}, (Register []){REG_V17_B0}, (Register []){REG_V18_B0}, (Register []){REG_V19_B0},
		(Register []){REG_V20_B0}, (Register []){REG_V21_B0}, (Register []){REG_V22_B0}, (Register []){REG_V23_B0},
		(Register []){REG_V24_B0}, (Register []){REG_V25_B0}, (Register []){REG_V26_B0}, (Register []){REG_V27_B0},
		(Register []){REG_V28_B0}, (Register []){REG_V29_B0}, (Register []){REG_V30_B0}, (Register []){REG_V31_B0}
	}
};

Register v_consolidate_lookup[32][15] =
{ /* NONE .q .2d .4s .8h .16b .d .2s .4h .8b .s .2h .4b .h .b */
	{REG_V0, REG_V0, REG_V0, REG_V0, REG_V0, REG_V0, REG_V0_D0, REG_V0_D0, REG_V0_D0, REG_V0_D0, REG_V0_S0, REG_V0_S0, REG_V0_S0, REG_V0_H0, REG_V0_B0},
	{REG_V1, REG_V1, REG_V1, REG_V1, REG_V1, REG_V1, REG_V1_D0, REG_V1_D0, REG_V1_D0, REG_V1_D0, REG_V1_S0, REG_V1_S0, REG_V1_S0, REG_V1_H0, REG_V1_B0},
	{REG_V2, REG_V2, REG_V2, REG_V2, REG_V2, REG_V2, REG_V2_D0, REG_V2_D0, REG_V2_D0, REG_V2_D0, REG_V2_S0, REG_V2_S0, REG_V2_S0, REG_V2_H0, REG_V2_B0},
	{REG_V3, REG_V3, REG_V3, REG_V3, REG_V3, REG_V3, REG_V3_D0, REG_V3_D0, REG_V3_D0, REG_V3_D0, REG_V3_S0, REG_V3_S0, REG_V3_S0, REG_V3_H0, REG_V3_B0},
	{REG_V4, REG_V4, REG_V4, REG_V4, REG_V4, REG_V4, REG_V4_D0, REG_V4_D0, REG_V4_D0, REG_V4_D0, REG_V4_S0, REG_V4_S0, REG_V4_S0, REG_V4_H0, REG_V4_B0},
	{REG_V5, REG_V5, REG_V5, REG_V5, REG_V5, REG_V5, REG_V5_D0, REG_V5_D0, REG_V5_D0, REG_V5_D0, REG_V5_S0, REG_V5_S0, REG_V5_S0, REG_V5_H0, REG_V5_B0},
	{REG_V6, REG_V6, REG_V6, REG_V6, REG_V6, REG_V6, REG_V6_D0, REG_V6_D0, REG_V6_D0, REG_V6_D0, REG_V6_S0, REG_V6_S0, REG_V6_S0, REG_V6_H0, REG_V6_B0},
	{REG_V7, REG_V7, REG_V7, REG_V7, REG_V7, REG_V7, REG_V7_D0, REG_V7_D0, REG_V7_D0, REG_V7_D0, REG_V7_S0, REG_V7_S0, REG_V7_S0, REG_V7_H0, REG_V7_B0},
	{REG_V8, REG_V8, REG_V8, REG_V8, REG_V8, REG_V8, REG_V8_D0, REG_V8_D0, REG_V8_D0, REG_V8_D0, REG_V8_S0, REG_V8_S0, REG_V8_S0, REG_V8_H0, REG_V8_B0},
	{REG_V9, REG_V9, REG_V9, REG_V9, REG_V9, REG_V9, REG_V9_D0, REG_V9_D0, REG_V9_D0, REG_V9_D0, REG_V9_S0, REG_V9_S0, REG_V9_S0, REG_V9_H0, REG_V9_B0},
	{REG_V10, REG_V10, REG_V10, REG_V10, REG_V10, REG_V10, REG_V10_D0, REG_V10_D0, REG_V10_D0, REG_V10_D0, REG_V10_S0, REG_V10_S0, REG_V10_S0, REG_V10_H0, REG_V10_B0},
	{REG_V11, REG_V11, REG_V11, REG_V11, REG_V11, REG_V11, REG_V11_D0, REG_V11_D0, REG_V11_D0, REG_V11_D0, REG_V11_S0, REG_V11_S0, REG_V11_S0, REG_V11_H0, REG_V11_B0},
	{REG_V12, REG_V12, REG_V12, REG_V12, REG_V12, REG_V12, REG_V12_D0, REG_V12_D0, REG_V12_D0, REG_V12_D0, REG_V12_S0, REG_V12_S0, REG_V12_S0, REG_V12_H0, REG_V12_B0},
	{REG_V13, REG_V13, REG_V13, REG_V13, REG_V13, REG_V13, REG_V13_D0, REG_V13_D0, REG_V13_D0, REG_V13_D0, REG_V13_S0, REG_V13_S0, REG_V13_S0, REG_V13_H0, REG_V13_B0},
	{REG_V14, REG_V14, REG_V14, REG_V14, REG_V14, REG_V14, REG_V14_D0, REG_V14_D0, REG_V14_D0, REG_V14_D0, REG_V14_S0, REG_V14_S0, REG_V14_S0, REG_V14_H0, REG_V14_B0},
	{REG_V15, REG_V15, REG_V15, REG_V15, REG_V15, REG_V15, REG_V15_D0, REG_V15_D0, REG_V15_D0, REG_V15_D0, REG_V15_S0, REG_V15_S0, REG_V15_S0, REG_V15_H0, REG_V15_B0},
	{REG_V16, REG_V16, REG_V16, REG_V16, REG_V16, REG_V16, REG_V16_D0, REG_V16_D0, REG_V16_D0, REG_V16_D0, REG_V16_S0, REG_V16_S0, REG_V16_S0, REG_V16_H0, REG_V16_B0},
	{REG_V17, REG_V17, REG_V17, REG_V17, REG_V17, REG_V17, REG_V17_D0, REG_V17_D0, REG_V17_D0, REG_V17_D0, REG_V17_S0, REG_V17_S0, REG_V17_S0, REG_V17_H0, REG_V17_B0},
	{REG_V18, REG_V18, REG_V18, REG_V18, REG_V18, REG_V18, REG_V18_D0, REG_V18_D0, REG_V18_D0, REG_V18_D0, REG_V18_S0, REG_V18_S0, REG_V18_S0, REG_V18_H0, REG_V18_B0},
	{REG_V19, REG_V19, REG_V19, REG_V19, REG_V19, REG_V19, REG_V19_D0, REG_V19_D0, REG_V19_D0, REG_V19_D0, REG_V19_S0, REG_V19_S0, REG_V19_S0, REG_V19_H0, REG_V19_B0},
	{REG_V20, REG_V20, REG_V20, REG_V20, REG_V20, REG_V20, REG_V20_D0, REG_V20_D0, REG_V20_D0, REG_V20_D0, REG_V20_S0, REG_V20_S0, REG_V20_S0, REG_V20_H0, REG_V20_B0},
	{REG_V21, REG_V21, REG_V21, REG_V21, REG_V21, REG_V21, REG_V21_D0, REG_V21_D0, REG_V21_D0, REG_V21_D0, REG_V21_S0, REG_V21_S0, REG_V21_S0, REG_V21_H0, REG_V21_B0},
	{REG_V22, REG_V22, REG_V22, REG_V22, REG_V22, REG_V22, REG_V22_D0, REG_V22_D0, REG_V22_D0, REG_V22_D0, REG_V22_S0, REG_V22_S0, REG_V22_S0, REG_V22_H0, REG_V22_B0},
	{REG_V23, REG_V23, REG_V23, REG_V23, REG_V23, REG_V23, REG_V23_D0, REG_V23_D0, REG_V23_D0, REG_V23_D0, REG_V23_S0, REG_V23_S0, REG_V23_S0, REG_V23_H0, REG_V23_B0},
	{REG_V24, REG_V24, REG_V24, REG_V24, REG_V24, REG_V24, REG_V24_D0, REG_V24_D0, REG_V24_D0, REG_V24_D0, REG_V24_S0, REG_V24_S0, REG_V24_S0, REG_V24_H0, REG_V24_B0},
	{REG_V25, REG_V25, REG_V25, REG_V25, REG_V25, REG_V25, REG_V25_D0, REG_V25_D0, REG_V25_D0, REG_V25_D0, REG_V25_S0, REG_V25_S0, REG_V25_S0, REG_V25_H0, REG_V25_B0},
	{REG_V26, REG_V26, REG_V26, REG_V26, REG_V26, REG_V26, REG_V26_D0, REG_V26_D0, REG_V26_D0, REG_V26_D0, REG_V26_S0, REG_V26_S0, REG_V26_S0, REG_V26_H0, REG_V26_B0},
	{REG_V27, REG_V27, REG_V27, REG_V27, REG_V27, REG_V27, REG_V27_D0, REG_V27_D0, REG_V27_D0, REG_V27_D0, REG_V27_S0, REG_V27_S0, REG_V27_S0, REG_V27_H0, REG_V27_B0},
	{REG_V28, REG_V28, REG_V28, REG_V28, REG_V28, REG_V28, REG_V28_D0, REG_V28_D0, REG_V28_D0, REG_V28_D0, REG_V28_S0, REG_V28_S0, REG_V28_S0, REG_V28_H0, REG_V28_B0},
	{REG_V29, REG_V29, REG_V29, REG_V29, REG_V29, REG_V29, REG_V29_D0, REG_V29_D0, REG_V29_D0, REG_V29_D0, REG_V29_S0, REG_V29_S0, REG_V29_S0, REG_V29_H0, REG_V29_B0},
	{REG_V30, REG_V30, REG_V30, REG_V30, REG_V30, REG_V30, REG_V30_D0, REG_V30_D0, REG_V30_D0, REG_V30_D0, REG_V30_S0, REG_V30_S0, REG_V30_S0, REG_V30_H0, REG_V30_B0},
	{REG_V31, REG_V31, REG_V31, REG_V31, REG_V31, REG_V31, REG_V31_D0, REG_V31_D0, REG_V31_D0, REG_V31_D0, REG_V31_S0, REG_V31_S0, REG_V31_S0, REG_V31_H0, REG_V31_B0},
};


static int unpack_vector(InstructionOperand& oper, Register *result)
{
	if(oper.operandClass == REG) {
		/* register without an arrangement specification is just a register
			examples: "d18", "d6", "v7" */
		if(oper.arrSpec==ARRSPEC_NONE) {
			result[0] = oper.reg[0];
			return 1;
		}

		/* require V register with valid arrangement spec
			examples: "v17.2s", "v8.4h", "v21.8b" */
		if(oper.reg[0]<REG_V0 || oper.reg[0]>REG_V31)
			return 0;
		if(oper.arrSpec<=ARRSPEC_NONE || oper.arrSpec>ARRSPEC_1BYTE)
			return 0;

		/* lookup, copy result */
		int n = v_unpack_lookup_sz[oper.arrSpec];
		for(int i=0; i<n; ++i)
			result[i] = v_unpack_lookup[oper.arrSpec][oper.reg[0]-REG_V0][i];
		return n;
	}
	else if(oper.operandClass == MULTI_REG) {
		if(oper.laneUsed) {
			// TODO: multireg with a lane
			return 0;
		}
		else {
			/* multireg without a lane
				examples: "{v0.8b, v1.8b}", "{v8.2s, v9.2s}" */
			if(oper.arrSpec<ARRSPEC_NONE || oper.arrSpec>ARRSPEC_1BYTE)
				return 0;

			int n = 0;
			for(int i=0; i<4 && oper.reg[i]!=REG_NONE; i++) {
				result[i] = v_consolidate_lookup[oper.reg[i]-REG_V0][oper.arrSpec];
				n += 1;
			}
			return n;
		}
	}

	return 0;
}


static void LoadStoreOperandPair(
		LowLevelILFunction& il,
		bool load,
		InstructionOperand& operand1,
		InstructionOperand& operand2,
		InstructionOperand& operand3)
{
	unsigned sz = REGSZ(operand1);

	/* do pre-indexing */
	ExprId tmp = GetILOperandPreIndex(il, operand3);
	if(tmp) il.AddInstruction(tmp);

	/* compute addresses */
	OperandClass oclass = (operand3.operandClass == MEM_PRE_IDX) ? MEM_REG : operand3.operandClass;
	ExprId addr0 = GetILOperandEffectiveAddress(il, operand3, sz, oclass, 0);
	ExprId addr1 = GetILOperandEffectiveAddress(il, operand3, sz, oclass, sz);

	/* load/store */
	if(load) {
		il.AddInstruction(il.SetRegister(sz, REG(operand1), il.Load(sz, addr0)));
		il.AddInstruction(il.SetRegister(sz, REG(operand2), il.Load(sz, addr1)));
	}
	else {
		il.AddInstruction(il.Store(sz, addr0, ILREG(operand1)));
		il.AddInstruction(il.Store(sz, addr1, ILREG(operand2)));
	}

	/* do post-indexing */
	tmp = GetILOperandPostIndex(il, operand3);
	if(tmp) il.AddInstruction(tmp);
}

static void LoadVector(
		LowLevelILFunction& il,
		InstructionOperand& oper0,
		InstructionOperand& oper1
)
{
	/* do pre-indexing */
	ExprId tmp = GetILOperandPreIndex(il, oper1);
	if(tmp) il.AddInstruction(tmp);

	Register regs[16];
	int regs_n = unpack_vector(oper0, regs);

	/* if we pre-indexed, base sequential effective addresses off the base register */
	OperandClass oclass = (oper1.operandClass == MEM_PRE_IDX) ? MEM_REG : oper1.operandClass;

	/* generate loads */
	int offset = 0;
	for(int i=0; i<regs_n; ++i) {
		int rsize = get_register_size(regs[i]);
		il.AddInstruction(il.SetRegister(rsize, regs[i],
			il.Load(rsize, GetILOperandEffectiveAddress(il, oper1, 8, oclass, offset))));
		offset += rsize;
	}

	/* do post-indexing */
	tmp = GetILOperandPostIndex(il, oper1);
	if(tmp) il.AddInstruction(tmp);
}

static void LoadStoreOperand(
		LowLevelILFunction& il,
		bool load,
		InstructionOperand& operand1,
		InstructionOperand& operand2)
{
	ExprId tmp;
	if (load)
	{
		switch (operand2.operandClass)
		{
		case MEM_REG:
			//operand1.reg = [operand2.reg]
			il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1),
						il.Operand(1, il.Load(REGSZ(operand1), ILREG(operand2)))));
			break;
		case MEM_OFFSET:
			//operand1.reg = [operand2.reg + operand2.imm]
			if (IMM(operand2) == 0)
				tmp = ILREG(operand2);
			else
				tmp = il.Add(REGSZ(operand2), ILREG(operand2), il.Const(REGSZ(operand2), IMM(operand2)));

			il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1),
						il.Operand(1, il.Load(REGSZ(operand1), tmp))));
			break;
		case MEM_PRE_IDX:
			//operand2.reg += operand2.imm
			if (IMM(operand2) != 0)
				il.AddInstruction(il.SetRegister(REGSZ(operand2), REG(operand2),
							il.Add(REGSZ(operand2),
								ILREG(operand2),
								il.Const(REGSZ(operand2), IMM(operand2)))));
			//operand1.reg = [operand2.reg]
			il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1),
						il.Operand(1, il.Load(REGSZ(operand1), ILREG(operand2)))));
			break;
		case MEM_POST_IDX:
			//operand1.reg = [operand2.reg]
			il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1),
						il.Operand(1, il.Load(REGSZ(operand1), ILREG(operand2)))));
			//operand2.reg += operand2.imm
			if (IMM(operand2) != 0)
				il.AddInstruction(il.SetRegister(REGSZ(operand2), REG(operand2),
							il.Add(REGSZ(operand2),
								ILREG(operand2),
								il.Const(REGSZ(operand2), IMM(operand2)))));
			break;
		case MEM_EXTENDED:
			il.AddInstruction(
					il.SetRegister(REGSZ(operand1), REG(operand1),
						il.Operand(1,
							il.Load(REGSZ(operand1),
								il.Add(REGSZ(operand2),
									ILREG(operand2),
									GetShiftedRegister(il, operand2, 1, REGSZ(operand2))
									)))));
			break;
		case LABEL:
			il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1),
						il.Operand(1, il.Load(REGSZ(operand1), il.ConstPointer(8, IMM(operand2))))));
			break;
		case IMM32:
		case IMM64:
			il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1), il.Const(REGSZ(operand1), IMM(operand2))));
			break;
		default:
			il.AddInstruction(il.Unimplemented());
			break;
		}
	}
	else //store
	{
		switch (operand2.operandClass)
		{
		case MEM_REG:
			il.AddInstruction(il.Operand(1, il.Store(REGSZ(operand1), ILREG(operand2), ILREG(operand1))));
			break;
		case MEM_OFFSET:
			//[operand2.reg + operand2.immediate] = operand1.reg
			if (IMM(operand2) == 0)
				tmp = ILREG(operand2);
			else
				tmp = il.Add(REGSZ(operand2), ILREG(operand2), il.Const(REGSZ(operand2), IMM(operand2)));

			il.AddInstruction(il.Operand(1, il.Store(REGSZ(operand1), tmp, ILREG(operand1))));
			break;
		case MEM_PRE_IDX:
			//operand2.reg = operand2.reg + operand2.immediate
			if (IMM(operand2) != 0)
				il.AddInstruction(il.SetRegister(REGSZ(operand2), REG(operand2),
					il.Add(REGSZ(operand2), ILREG(operand2), il.Const(REGSZ(operand2), IMM(operand2)))));
			//[operand2.reg] = operand1.reg
			il.AddInstruction(il.Operand(1, il.Store(REGSZ(operand1), ILREG(operand2), ILREG(operand1))));
			break;
		case MEM_POST_IDX:
			//[operand2.reg] = operand1.reg
			il.AddInstruction(il.Operand(1, il.Store(REGSZ(operand1), ILREG(operand2), ILREG(operand1))));
			//operand2.reg = operand2.reg + operand2.immediate
			if (IMM(operand2) != 0)
				il.AddInstruction(il.SetRegister(REGSZ(operand2), REG(operand2),
					il.Add(REGSZ(operand2), ILREG(operand2), il.Const(REGSZ(operand2), IMM(operand2)))));
			break;
		case MEM_EXTENDED:
			il.AddInstruction(il.Operand(1, il.Store(REGSZ(operand1),
					il.Add(REGSZ(operand2),
						il.Register(REGSZ(operand2), operand2.reg[0]),
						GetShiftedRegister(il, operand2, 1, REGSZ(operand2))),
					ILREG(operand1))));
			break;
		default:
			il.AddInstruction(il.Unimplemented());
			break;
		}
	}
}

static void LoadStoreOperandSize(
		LowLevelILFunction& il,
		bool load,
		bool signedImm,
		size_t size,
		InstructionOperand& operand1,
		InstructionOperand& operand2)
{
	ExprId tmp;
	if (load)
	{

		switch (operand2.operandClass)
		{
		case MEM_REG:
			//operand1.reg = [operand2.reg]
			tmp = il.Operand(1, il.Load(size, ILREG(operand2)));

			if (signedImm)
				tmp = il.SignExtend(REGSZ(operand1), tmp);
			else
				tmp = il.ZeroExtend(REGSZ(operand1), tmp);

			il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1), tmp));
			break;
		case MEM_OFFSET:
			//operand1.reg = [operand2.reg + operand2.imm]
			if (IMM(operand2) == 0)
				tmp = ILREG(operand2);
			else
				tmp = il.Add(REGSZ(operand2), ILREG(operand2), il.Const(REGSZ(operand2), IMM(operand2)));

			tmp = il.Operand(1, il.Load(size, tmp));

			if (signedImm)
				tmp = il.SignExtend(REGSZ(operand1), tmp);
			else
				tmp = il.ZeroExtend(REGSZ(operand1), tmp);

			il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1), tmp));
			break;
		case MEM_PRE_IDX:
			//operand2.reg += operand2.imm
			if (IMM(operand2) != 0)
				il.AddInstruction(il.SetRegister(REGSZ(operand2), REG(operand2),
							il.Add(REGSZ(operand2),
								ILREG(operand2),
								il.Const(REGSZ(operand2), IMM(operand2)))));
			//operand1.reg = [operand2.reg]
			tmp = il.Operand(1, il.Load(size, ILREG(operand2)));

			if (signedImm)
				tmp = il.SignExtend(REGSZ(operand1), tmp);
			else
				tmp = il.ZeroExtend(REGSZ(operand1), tmp);

			il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1), tmp));
			break;
		case MEM_POST_IDX:
			//operand1.reg = [operand2.reg]
			tmp = il.Operand(1, il.Load(size, ILREG(operand2)));

			if (signedImm)
				tmp = il.SignExtend(REGSZ(operand1), tmp);
			else
				tmp = il.ZeroExtend(REGSZ(operand1), tmp);

			il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1), tmp));
			//operand2.reg += operand2.imm
			if (IMM(operand2) != 0)
				il.AddInstruction(il.SetRegister(REGSZ(operand2), REG(operand2),
							il.Add(REGSZ(operand2),
								ILREG(operand2),
								il.Const(REGSZ(operand2), IMM(operand2)))));
			break;
		case MEM_EXTENDED:
			tmp = il.Operand(1, il.Load(size,
						il.Add(REGSZ(operand2),
							ILREG(operand2),
							GetShiftedRegister(il, operand2, 1, REGSZ(operand2))
							)));

			if (signedImm)
				tmp = il.SignExtend(REGSZ(operand1), tmp);
			else
				tmp = il.ZeroExtend(REGSZ(operand1), tmp);

			il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1), tmp));
			break;
		default:
			il.AddInstruction(il.Unimplemented());
			break;
		}

	}
	else //store
	{
		ExprId valToStore = il.Operand(0, ILREG(operand1));

		if (size < REGSZ(operand1))
			valToStore = il.LowPart(size, valToStore);

		switch (operand2.operandClass)
		{
		case MEM_REG:
			il.AddInstruction(il.Operand(1, il.Store(size, ILREG(operand2), valToStore)));
			break;
		case MEM_OFFSET:
			//[operand2.reg + operand2.immediate] = operand1.reg
			if (IMM(operand2) == 0)
				tmp = il.Store(size, ILREG(operand2), valToStore);
			else
				tmp = il.Store(size,
					il.Add(REGSZ(operand2), ILREG(operand2), il.Const(REGSZ(operand2), IMM(operand2))),
					valToStore);
			il.AddInstruction(il.Operand(1, tmp));
			break;
		case MEM_PRE_IDX:
			//operand2.reg = operand2.reg + operand2.immediate
			if (IMM(operand2) != 0)
				il.AddInstruction(il.SetRegister(REGSZ(operand2), REG(operand2),
					il.Add(REGSZ(operand2), ILREG(operand2), il.Const(REGSZ(operand2), IMM(operand2)))));
			//[operand2.reg] = operand1.reg
			il.AddInstruction(il.Operand(1, il.Store(size, ILREG(operand2), valToStore)));
			break;
		case MEM_POST_IDX:
			//[operand2.reg] = operand1.reg
			il.AddInstruction(il.Operand(1, il.Store(size, ILREG(operand2), valToStore)));
			//operand2.reg = operand2.reg + operand2.immediate
			if (IMM(operand2) != 0)
				il.AddInstruction(il.SetRegister(REGSZ(operand2), REG(operand2),
					il.Add(REGSZ(operand2), ILREG(operand2), il.Const(REGSZ(operand2), IMM(operand2)))));
			break;
		case MEM_EXTENDED:
			il.AddInstruction(il.Operand(1, il.Store(size,
					il.Add(REGSZ(operand2),
						il.Register(REGSZ(operand2), operand2.reg[0]),
						GetShiftedRegister(il, operand2, 1, REGSZ(operand2))),
					valToStore)));
			break;
		default:
			il.AddInstruction(il.Unimplemented());
			break;
		}
	}
}


static size_t DirectJump(Architecture* arch, LowLevelILFunction& il, uint64_t target, size_t addrSize)
{
	BNLowLevelILLabel* label = il.GetLabelForAddress(arch, target);
	if (label)
		return il.Goto(*label);
	else
		return il.Jump(il.ConstPointer(addrSize, target));

	return 0;
}


static ExprId ExtractBits(LowLevelILFunction& il, InstructionOperand& reg, size_t nbits, size_t rightMostBit)
{
//Get N set bits at offset O
#define BITMASK(N,O) (((1LL << nbits) - 1) << O)
	return il.And(REGSZ(reg), ILREG(reg), il.Const(REGSZ(reg), BITMASK(nbits, rightMostBit)));
}

static ExprId ExtractBit(LowLevelILFunction& il, InstructionOperand& reg, size_t bit)
{
	return il.And(REGSZ(reg), ILREG(reg), il.Const(REGSZ(reg), (1<<bit)));
}

static void ConditionalJump(Architecture* arch, LowLevelILFunction& il, size_t cond, size_t addrSize, uint64_t t, uint64_t f)
{
	BNLowLevelILLabel* trueLabel = il.GetLabelForAddress(arch, t);
	BNLowLevelILLabel* falseLabel = il.GetLabelForAddress(arch, f);

	if (trueLabel && falseLabel)
	{
		il.AddInstruction(il.If(cond, *trueLabel, *falseLabel));
		return;
	}

	LowLevelILLabel trueCode, falseCode;

	if (trueLabel)
	{
		il.AddInstruction(il.If(cond, *trueLabel, falseCode));
		il.MarkLabel(falseCode);
		il.AddInstruction(il.Jump(il.ConstPointer(addrSize, f)));
		return;
	}

	if (falseLabel)
	{
		il.AddInstruction(il.If(cond, trueCode, *falseLabel));
		il.MarkLabel(trueCode);
		il.AddInstruction(il.Jump(il.ConstPointer(addrSize, t)));
		return;
	}

	il.AddInstruction(il.If(cond, trueCode, falseCode));
	il.MarkLabel(trueCode);
	il.AddInstruction(il.Jump(il.ConstPointer(addrSize, t)));
	il.MarkLabel(falseCode);
	il.AddInstruction(il.Jump(il.ConstPointer(addrSize, f)));
}


enum Arm64Intrinsic operation_to_intrinsic(int operation)
{
	switch(operation) {
		case ARM64_AUTDA: return ARM64_INTRIN_AUTDA;
		case ARM64_AUTDB: return ARM64_INTRIN_AUTDB;
		case ARM64_AUTIA: return ARM64_INTRIN_AUTIA;
		case ARM64_AUTIB: return ARM64_INTRIN_AUTIB;
		case ARM64_AUTIB1716: return ARM64_INTRIN_AUTIB1716;
		case ARM64_AUTIBSP: return ARM64_INTRIN_AUTIBSP;
		case ARM64_AUTIBZ: return ARM64_INTRIN_AUTIBZ;
		case ARM64_AUTDZA: return ARM64_INTRIN_AUTDZA;
		case ARM64_AUTDZB: return ARM64_INTRIN_AUTDZB;
		case ARM64_AUTIZA: return ARM64_INTRIN_AUTIZA;
		case ARM64_AUTIZB: return ARM64_INTRIN_AUTIZB;
		case ARM64_PACDA: return ARM64_INTRIN_PACDA;
		case ARM64_PACDB: return ARM64_INTRIN_PACDB;
		case ARM64_PACDZA: return ARM64_INTRIN_PACDZA;
		case ARM64_PACDZB: return ARM64_INTRIN_PACDZB;
		case ARM64_PACGA: return ARM64_INTRIN_PACGA;
		case ARM64_PACIA: return ARM64_INTRIN_PACIA;
		case ARM64_PACIA1716: return ARM64_INTRIN_PACIA1716;
		case ARM64_PACIASP: return ARM64_INTRIN_PACIASP;
		case ARM64_PACIAZ: return ARM64_INTRIN_PACIAZ;
		case ARM64_PACIB: return ARM64_INTRIN_PACIB;
		case ARM64_PACIB1716: return ARM64_INTRIN_PACIB1716;
		case ARM64_PACIBSP: return ARM64_INTRIN_PACIBSP;
		case ARM64_PACIBZ: return ARM64_INTRIN_PACIBZ;
		case ARM64_PACIZA: return ARM64_INTRIN_PACIZA;
		case ARM64_PACIZB: return ARM64_INTRIN_PACIZB;
		case ARM64_XPACD: return ARM64_INTRIN_XPACD;
		case ARM64_XPACI: return ARM64_INTRIN_XPACI;
		case ARM64_XPACLRI: return ARM64_INTRIN_XPACLRI;
		default:
			return ARM64_INTRIN_INVALID;
	}
}


bool GetLowLevelILForInstruction(Architecture* arch, uint64_t addr, LowLevelILFunction& il, Instruction& instr, size_t addrSize)
{
	InstructionOperand& operand1 = instr.operands[0];
	InstructionOperand& operand2 = instr.operands[1];
	InstructionOperand& operand3 = instr.operands[2];
	InstructionOperand& operand4 = instr.operands[3];

	LowLevelILLabel trueLabel, falseLabel;
	switch (instr.operation)
	{
	case ARM64_ADD:
	case ARM64_ADDS:
		il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1),
					il.Add(REGSZ(operand1),
						ILREG(operand2),
						ReadILOperand(il, operand3, REGSZ(operand1)),
						SETFLAGS)));
		break;
	case ARM64_ADC:
	case ARM64_ADCS:
		il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1),
					il.AddCarry(REGSZ(operand1),
						ILREG(operand2),
						ReadILOperand(il, operand3, REGSZ(operand1)),
						il.Flag(IL_FLAG_C),
						SETFLAGS)));
		break;
	case ARM64_AND:
	case ARM64_ANDS:
		il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1),
					il.And(REGSZ(operand1),
						ILREG(operand2),
						ReadILOperand(il, operand3, REGSZ(operand1)),
						SETFLAGS)));
		break;
	case ARM64_ADR:
	case ARM64_ADRP:
		il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1), il.ConstPointer(REGSZ(operand1), IMM(operand2))));
		break;
	case ARM64_ASR:
		il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1), il.ArithShiftRight(REGSZ(operand2), ILREG(operand2), il.Const(REGSZ(operand2), IMM(operand3)))));
		break;
	case ARM64_AESD:
		il.AddInstruction(il.Intrinsic({RegisterOrFlag::Register(REG(operand1))}, ARM64_INTRIN_AESD, {ILREG(operand1), ILREG(operand2)}));
		break;
	case ARM64_AESE:
		il.AddInstruction(il.Intrinsic({RegisterOrFlag::Register(REG(operand1))}, ARM64_INTRIN_AESE, {ILREG(operand1), ILREG(operand2)}));
		break;
	case ARM64_BTI:
		il.AddInstruction(il.Intrinsic({}, ARM64_INTRIN_HINT_BTI, {}));
		break;
	case ARM64_B:
		il.AddInstruction(DirectJump(arch, il, IMM(operand1), addrSize));
		break;
	case ARM64_B_NE:
		ConditionalJump(arch, il, il.FlagCondition(LLFC_NE), addrSize, IMM(operand1), addr + 4);
		return false;
	case ARM64_B_EQ:
		ConditionalJump(arch, il, il.FlagCondition(LLFC_E), addrSize, IMM(operand1), addr + 4);
		return false;
	case ARM64_B_CS:
		ConditionalJump(arch, il, il.FlagCondition(LLFC_UGE), addrSize, IMM(operand1), addr + 4);
		return false;
	case ARM64_B_CC:
		ConditionalJump(arch, il, il.FlagCondition(LLFC_ULT), addrSize, IMM(operand1), addr + 4);
		return false;
	case ARM64_B_MI:
		ConditionalJump(arch, il, il.FlagCondition(LLFC_NEG), addrSize, IMM(operand1), addr + 4);
		return false;
	case ARM64_B_PL:
		ConditionalJump(arch, il, il.FlagCondition(LLFC_POS), addrSize, IMM(operand1), addr + 4);
		return false;
	case ARM64_B_VS:
		ConditionalJump(arch, il, il.FlagCondition(LLFC_O), addrSize, IMM(operand1), addr + 4);
		return false;
	case ARM64_B_VC:
		ConditionalJump(arch, il, il.FlagCondition(LLFC_NO), addrSize, IMM(operand1), addr + 4);
		return false;
	case ARM64_B_HI:
		ConditionalJump(arch, il, il.FlagCondition(LLFC_UGT), addrSize, IMM(operand1), addr + 4);
		return false;
	case ARM64_B_LS:
		ConditionalJump(arch, il, il.FlagCondition(LLFC_ULE), addrSize, IMM(operand1), addr + 4);
		return false;
	case ARM64_B_GE:
		ConditionalJump(arch, il, il.FlagCondition(LLFC_SGE), addrSize, IMM(operand1), addr + 4);
		return false;
	case ARM64_B_LT:
		ConditionalJump(arch, il, il.FlagCondition(LLFC_SLT), addrSize, IMM(operand1), addr + 4);
		return false;
	case ARM64_B_GT:
		ConditionalJump(arch, il, il.FlagCondition(LLFC_SGT), addrSize, IMM(operand1), addr + 4);
		return false;
	case ARM64_B_LE:
		ConditionalJump(arch, il, il.FlagCondition(LLFC_SLE), addrSize, IMM(operand1), addr + 4);
		return false;
	case ARM64_BL:
		il.AddInstruction(il.Call(il.ConstPointer(addrSize, IMM(operand1))));
		break;
	case ARM64_BLR:
	case ARM64_BLRAA:
	case ARM64_BLRAAZ:
	case ARM64_BLRAB:
	case ARM64_BLRABZ:
		il.AddInstruction(il.Call(ILREG(operand1)));
		break;
	case ARM64_BFC:
		il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1),
			il.And(REGSZ(operand1),
				il.Const(REGSZ(operand1), ~(ONES(IMM(operand3)) << IMM(operand2))),
				ILREG(operand1))));
		break;
	case ARM64_BFI:
		il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1),
			il.Or(REGSZ(operand1),
				il.And(REGSZ(operand1),
					il.Const(REGSZ(operand1), ~(ONES(IMM(operand4)) << IMM(operand3))),
					ILREG(operand1)),
				il.ShiftLeft(REGSZ(operand1),
					il.And(REGSZ(operand1),
						il.Const(REGSZ(operand1), ONES(IMM(operand4))),
						ILREG(operand2)),
					il.Const(0, IMM(operand3))))));
		break;
	case ARM64_BFXIL:
		il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1),
			il.Or(REGSZ(operand1),
				il.And(REGSZ(operand1),
					ILREG(operand1),
					il.Const(REGSZ(operand1), ~ONES(IMM(operand4)))),
				il.LogicalShiftRight(REGSZ(operand1),
					il.And(REGSZ(operand1),
						ILREG(operand2),
						il.Const(REGSZ(operand1), ONES(IMM(operand4)) << IMM(operand3))),
					il.Const(0, IMM(operand3))))));
		break;
	case ARM64_BR:
	case ARM64_BRAA:
	case ARM64_BRAAZ:
	case ARM64_BRAB:
	case ARM64_BRABZ:
		il.AddInstruction(il.Jump(ILREG(operand1)));
		return false;
	case ARM64_BIC:
	case ARM64_BICS:
		il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1),
					il.And(REGSZ(operand2),
						ILREG(operand2),
						il.Not(REGSZ(operand2),
							ReadILOperand(il, operand3, REGSZ(operand2))), SETFLAGS)
							));
		break;
	case ARM64_CAS: // these compare-and-swaps can be 32 or 64 bit
	case ARM64_CASA:
	case ARM64_CASAL:
	case ARM64_CASL:
		GenIfElse(il,
			il.CompareEqual(REGSZ(operand1), ILREG(operand1), il.Load(REGSZ(operand1), ILREG(operand3))),
			il.Store(REGSZ(operand1), ILREG(operand3), ILREG(operand2)),
			0
		);
		break;
	case ARM64_CASAH: // these compare-and-swaps are 16 bit
	case ARM64_CASALH:
	case ARM64_CASH:
	case ARM64_CASLH:
		GenIfElse(il,
			il.CompareEqual(REGSZ(operand1), ExtractRegister(il, operand1, 0, 2, false, 2), il.Load(2, ILREG(operand3))),
			il.Store(2, ILREG(operand3), ExtractRegister(il, operand2, 0, 2, false, 2)),
			0
		);
		break;
	case ARM64_CASAB: // these compare-and-swaps are 8 bit
	case ARM64_CASALB:
	case ARM64_CASB:
	case ARM64_CASLB:
		GenIfElse(il,
			il.CompareEqual(REGSZ(operand1), ExtractRegister(il, operand1, 0, 1, false, 1), il.Load(1, ILREG(operand3))),
			il.Store(1, ILREG(operand3), ExtractRegister(il, operand2, 0, 1, false, 1)),
			0
		);
		break;
	case ARM64_CBNZ:
		ConditionalJump(arch, il,
				il.CompareNotEqual(REGSZ(operand1),
					ILREG(operand1),
					il.Const(REGSZ(operand1), 0)),
				addrSize, IMM(operand2), addr + 4);
		return false;
	case ARM64_CBZ:
		ConditionalJump(arch, il,
				il.CompareEqual(REGSZ(operand1),
					ILREG(operand1),
					il.Const(REGSZ(operand1), 0)),
				addrSize, IMM(operand2), addr + 4);
		return false;
	case ARM64_CMN:
		il.AddInstruction(il.Add(REGSZ(operand1),
					ILREG(operand1),
					ReadILOperand(il, operand2, REGSZ(operand1)), SETFLAGS));
		break;
	case ARM64_CCMN:
		{
			LowLevelILLabel trueCode, falseCode, done;

			il.AddInstruction(il.If(GetCondition(il, operand4.cond), trueCode, falseCode));

			il.MarkLabel(trueCode);
			il.AddInstruction(il.Add(REGSZ(operand1),
						ILREG(operand1),
						ReadILOperand(il, operand2, REGSZ(operand1)), SETFLAGS));
			il.AddInstruction(il.Goto(done));

			il.MarkLabel(falseCode);
			il.AddInstruction(il.SetFlag(IL_FLAG_N, il.Const(0, (IMM(operand3) >> 3) & 1)));
			il.AddInstruction(il.SetFlag(IL_FLAG_Z, il.Const(0, (IMM(operand3) >> 2) & 1)));
			il.AddInstruction(il.SetFlag(IL_FLAG_C, il.Const(0, (IMM(operand3) >> 1) & 1)));
			il.AddInstruction(il.SetFlag(IL_FLAG_V, il.Const(0, (IMM(operand3) >> 0) & 1)));

			il.AddInstruction(il.Goto(done));

			il.MarkLabel(done);
		}
		break;
	case ARM64_CMP:
		il.AddInstruction(il.Sub(REGSZ(operand1),
					ILREG(operand1),
					ReadILOperand(il, operand2, REGSZ(operand1)), SETFLAGS));
		break;
	case ARM64_CCMP:
		{
			LowLevelILLabel trueCode, falseCode, done;

			il.AddInstruction(il.If(GetCondition(il, operand4.cond), trueCode, falseCode));

			il.MarkLabel(trueCode);
			il.AddInstruction(il.Sub(REGSZ(operand1),
						ILREG(operand1),
						ReadILOperand(il, operand2, REGSZ(operand1)), SETFLAGS));
			il.AddInstruction(il.Goto(done));

			il.MarkLabel(falseCode);
			il.AddInstruction(il.SetFlag(IL_FLAG_N, il.Const(0, (IMM(operand3) >> 3) & 1)));
			il.AddInstruction(il.SetFlag(IL_FLAG_Z, il.Const(0, (IMM(operand3) >> 2) & 1)));
			il.AddInstruction(il.SetFlag(IL_FLAG_C, il.Const(0, (IMM(operand3) >> 1) & 1)));
			il.AddInstruction(il.SetFlag(IL_FLAG_V, il.Const(0, (IMM(operand3) >> 0) & 1)));

			il.AddInstruction(il.Goto(done));

			il.MarkLabel(done);
		}
		break;
	case ARM64_CSEL:
		GenIfElse(il, GetCondition(il, operand4.cond),
			il.SetRegister(REGSZ(operand1), REG(operand1), ILREG(operand2)),
			il.SetRegister(REGSZ(operand1), REG(operand1), ILREG(operand3)));
		break;
	case ARM64_CSINC:
		GenIfElse(il, GetCondition(il, operand4.cond),
			il.SetRegister(REGSZ(operand1), REG(operand1), ILREG(operand2)),
			il.SetRegister(REGSZ(operand1), REG(operand1), il.Add(REGSZ(operand1), ILREG(operand3), il.Const(REGSZ(operand1), 1))));
		break;
	case ARM64_CSINV:
		GenIfElse(il, GetCondition(il, operand4.cond),
			il.SetRegister(REGSZ(operand1), REG(operand1), ILREG(operand2)),
			il.SetRegister(REGSZ(operand1), REG(operand1), il.Not(REGSZ(operand1), ILREG(operand3))));
		break;
	case ARM64_CSNEG:
		GenIfElse(il, GetCondition(il, operand4.cond),
			il.SetRegister(REGSZ(operand1), REG(operand1), ILREG(operand2)),
			il.SetRegister(REGSZ(operand1), REG(operand1), il.Neg(REGSZ(operand1), ILREG(operand3))));
		break;
	case ARM64_CSET:
		GenIfElse(il, GetCondition(il, operand2.cond),
			il.SetRegister(REGSZ(operand1), REG(operand1), il.Const(REGSZ(operand1), 1)),
			il.SetRegister(REGSZ(operand1), REG(operand1), il.Const(REGSZ(operand1), 0)));
		break;
	case ARM64_CSETM:
		GenIfElse(il, GetCondition(il, operand2.cond),
			il.SetRegister(REGSZ(operand1), REG(operand1), il.Const(REGSZ(operand1), -1)),
			il.SetRegister(REGSZ(operand1), REG(operand1), il.Const(REGSZ(operand1), 0)));
		break;
	case ARM64_CINC:
		GenIfElse(il, GetCondition(il, operand3.cond),
			il.SetRegister(REGSZ(operand1), REG(operand1), il.Add(REGSZ(operand1), ILREG(operand2), il.Const(REGSZ(operand1), 1))),
			il.SetRegister(REGSZ(operand1), REG(operand1), ILREG(operand2)));
		break;
	case ARM64_CINV:
		GenIfElse(il, GetCondition(il, operand3.cond),
			il.SetRegister(REGSZ(operand1), REG(operand1), il.Not(REGSZ(operand1), ILREG(operand2))),
			il.SetRegister(REGSZ(operand1), REG(operand1), ILREG(operand2)));
		break;
	case ARM64_CNEG:
		GenIfElse(il, GetCondition(il, operand3.cond),
			il.SetRegister(REGSZ(operand1), REG(operand1), il.Neg(REGSZ(operand1), ILREG(operand2))),
			il.SetRegister(REGSZ(operand1), REG(operand1), ILREG(operand2)));
		break;
	case ARM64_CLZ:
		il.AddInstruction(il.Intrinsic({RegisterOrFlag::Register(REG(operand1))}, ARM64_INTRIN_CLZ, {ILREG(operand2)}));
		break;
	case ARM64_DMB:
		il.AddInstruction(il.Intrinsic({}, ARM64_INTRIN_DMB, {}));
		break;
	case ARM64_DSB:
		il.AddInstruction(il.Intrinsic({}, ARM64_INTRIN_DSB, {}));
		break;
	case ARM64_EON:
		il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1),
					il.Xor(REGSZ(operand1),
						ILREG(operand2),
						il.Not(REGSZ(operand1), ReadILOperand(il, operand3, REGSZ(operand1))))));
		break;
	case ARM64_EOR:
		il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1),
					il.Xor(REGSZ(operand1),
						ILREG(operand2),
						ReadILOperand(il, operand3, REGSZ(operand1)))));
		break;
	case ARM64_ESB:
		il.AddInstruction(il.Intrinsic({}, ARM64_INTRIN_ESB, {}));
		break;
	case ARM64_EXTR:
		il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1),
					il.LogicalShiftRight(REGSZ(operand1) * 2,
						il.Or(REGSZ(operand1) * 2,
							il.ShiftLeft(REGSZ(operand1) * 2, ILREG(operand2), il.Const(1, REGSZ(operand1) * 8)),
							ILREG(operand3)),
						il.Const(1, IMM(operand4)))));
		break;
	case ARM64_FADD:
		switch(instr.encoding) {
			case ENC_FADD_H_FLOATDP2:
			case ENC_FADD_S_FLOATDP2:
			case ENC_FADD_D_FLOATDP2:
				il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1),
					il.FloatAdd(REGSZ(operand1), ILREG(operand2), ILREG(operand3))));
				break;
			default:
				il.AddInstruction(il.Unimplemented());
		}
		break;
	case ARM64_FSUB:
		switch(instr.encoding) {
			case ENC_FSUB_H_FLOATDP2:
			case ENC_FSUB_S_FLOATDP2:
			case ENC_FSUB_D_FLOATDP2:
				il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1),
					il.FloatSub(REGSZ(operand1), ILREG(operand2), ILREG(operand3))));
				break;
			default:
				il.AddInstruction(il.Unimplemented());
		}
		break;
	case ARM64_FMUL:
		switch(instr.encoding) {
			case ENC_FMUL_H_FLOATDP2:
			case ENC_FMUL_S_FLOATDP2:
			case ENC_FMUL_D_FLOATDP2:
				il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1),
					il.FloatMult(REGSZ(operand1), ILREG(operand2), ILREG(operand3))));
				break;
			default:
				il.AddInstruction(il.Unimplemented());
		}
		break;
	case ARM64_FDIV:
		switch(instr.encoding) {
			case ENC_FDIV_H_FLOATDP2:
			case ENC_FDIV_S_FLOATDP2:
			case ENC_FDIV_D_FLOATDP2:
				il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1),
					il.FloatDiv(REGSZ(operand1), ILREG(operand2), ILREG(operand3))));
				break;
			default:
				il.AddInstruction(il.Unimplemented());
		}
		break;
	case ARM64_FMOV:
		switch(instr.encoding) {
			case ENC_FMOV_32H_FLOAT2INT:
			case ENC_FMOV_32S_FLOAT2INT:
			case ENC_FMOV_64D_FLOAT2INT:
			case ENC_FMOV_64H_FLOAT2INT:
			case ENC_FMOV_D64_FLOAT2INT:
			case ENC_FMOV_H32_FLOAT2INT:
			case ENC_FMOV_H64_FLOAT2INT:
			case ENC_FMOV_S32_FLOAT2INT:
				il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1),
					il.FloatToInt(REGSZ(operand1), ILREG(instr.operands[1]))));
				break;
			case ENC_FMOV_H_FLOATIMM:
			case ENC_FMOV_S_FLOATIMM:
			case ENC_FMOV_D_FLOATIMM:
				il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1),
					GetFloat(il, instr, operand2)));
				break;
			default:
				il.AddInstruction(il.Unimplemented());
		}
		break;
	case ARM64_ERET:
	case ARM64_ERETAA:
	case ARM64_ERETAB:
		il.AddInstruction(il.Intrinsic({}, ARM64_INTRIN_ERET, {}));
		il.AddInstruction(il.Trap(0));
		return false;
	case ARM64_ISB:
		il.AddInstruction(il.Intrinsic({}, ARM64_INTRIN_ISB, {}));
		break;
	case ARM64_LDAR:
	case ARM64_LDAXR:
		LoadStoreOperand(il, true, instr.operands[0], instr.operands[1]);
		break;
	case ARM64_LDARB:
	case ARM64_LDAXRB:
		LoadStoreOperandSize(il, true, false, 1, instr.operands[0], instr.operands[1]);
		break;
	case ARM64_LDARH:
	case ARM64_LDAXRH:
		LoadStoreOperandSize(il, true, false, 2, instr.operands[0], instr.operands[1]);
		break;
	case ARM64_LDP:
		LoadStoreOperandPair(il, true, instr.operands[0], instr.operands[1], instr.operands[2]);
		break;
	case ARM64_LDR:
	case ARM64_LDUR:
	case ARM64_LDRAA:
	case ARM64_LDRAB:
		LoadStoreOperand(il, true, instr.operands[0], instr.operands[1]);
		break;
	case ARM64_LDRB:
	case ARM64_LDURB:
		LoadStoreOperandSize(il, true, false, 1, instr.operands[0], instr.operands[1]);
		break;
	case ARM64_LDRH:
	case ARM64_LDURH:
		LoadStoreOperandSize(il, true, false, 2, instr.operands[0], instr.operands[1]);
		break;
	case ARM64_LDRSB:
	case ARM64_LDURSB:
		LoadStoreOperandSize(il, true, true, 1, instr.operands[0], instr.operands[1]);
		break;
	case ARM64_LDRSH:
	case ARM64_LDURSH:
		LoadStoreOperandSize(il, true, true, 2, instr.operands[0], instr.operands[1]);
		break;
	case ARM64_LDRSW:
	case ARM64_LDURSW:
		LoadStoreOperandSize(il, true, true, 4, instr.operands[0], instr.operands[1]);
		break;
	case ARM64_LD1:
	{
		LoadVector(il, instr.operands[0], instr.operands[1]);
		break;
	}
	case ARM64_ST1:
	{
		Register srcs[16];
		int src_n = unpack_vector(operand1, srcs);

		int offset = 0;
		for(int i=0; i<src_n; ++i) {
			int rsize = get_register_size(srcs[i]);
			il.AddInstruction(il.Store(rsize,
				GetILOperandEffectiveAddress(il, operand2, 8, NONE, offset),
				il.Register(rsize, srcs[i])));
			offset += rsize;
		}

		break;
	}
	case ARM64_LSL:
		il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1),
					il.ShiftLeft(REGSZ(operand2),
						ILREG(operand2),
						ReadILOperand(il, operand3, REGSZ(operand2)))));
		break;
	case ARM64_LSR:
		il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1),
					il.LogicalShiftRight(REGSZ(operand2),
						ILREG(operand2),
						ReadILOperand(il, operand3, REGSZ(operand2)))));
		break;
	case ARM64_MOV:
		il.AddInstruction(il.SetRegister(REGSZ(operand1),
					REG(operand1),
					ReadILOperand(il, instr.operands[1], REGSZ(operand1))));
		break;
	case ARM64_MVN:
		il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1),
						il.Not(REGSZ(operand1), ReadILOperand(il, operand2, REGSZ(operand1)))));
		break;
	case ARM64_MOVK:
		il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1),
					il.Or(REGSZ(operand1), ILREG(operand1), il.Const(REGSZ(operand1), IMM(operand2) << operand2.shiftValue))));
		break;
	case ARM64_MOVZ:
		il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1),
					il.Const(REGSZ(operand1), IMM(operand2) << operand2.shiftValue)));
		break;
	case ARM64_MUL:
		il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1),
					il.Mult(REGSZ(operand1), ILREG(operand2), ILREG(operand3))));
		break;
	case ARM64_MADD:
		il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1),
					il.Add(REGSZ(operand1), ILREG(operand4), il.Mult(REGSZ(operand1), ILREG(operand2), ILREG(operand3)))));
		break;
	case ARM64_MRS:
		{
			ExprId reg = ILREG(operand2);
			const char *name = get_system_register_name((SystemReg)operand2.sysreg);

			if (strlen(name) == 0) {
				LogWarn("Unknown system register %d @ 0x%" PRIx64 ": S%d_%d_c%d_c%d_%d, using catch-all system register instead\n",
						operand2.sysreg, addr, operand2.implspec[0], operand2.implspec[1], operand2.implspec[2],
						operand2.implspec[3], operand2.implspec[4]);
				reg = il.Register(8, SYSREG_UNKNOWN);
			}

			il.AddInstruction(il.Intrinsic({RegisterOrFlag::Register(REG(operand1))},
						ARM64_INTRIN_MRS,
						{reg}));
			break;
		}
	case ARM64_MSUB:
		il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1),
					il.Sub(REGSZ(operand1), ILREG(operand4), il.Mult(REGSZ(operand1), ILREG(operand2), ILREG(operand3)))));
		break;
	case ARM64_MNEG:
		il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1),
					il.Sub(REGSZ(operand1),
						il.Const(8, 0),
						il.Mult(REGSZ(operand1), ILREG(operand2), ILREG(operand3)))));
		break;
	case ARM64_MSR:
		{
			uint32_t dst = operand1.sysreg;
			const char *name = get_system_register_name((SystemReg)dst);

			if (strlen(name) == 0) {
				LogWarn("Unknown system register %d @ 0x%" PRIx64 ": S%d_%d_c%d_c%d_%d, using catch-all system register instead\n",
						dst, addr, operand1.implspec[0], operand1.implspec[1], operand1.implspec[2],
						operand1.implspec[3], operand1.implspec[4]);
				dst = SYSREG_UNKNOWN;
			}

			switch (operand2.operandClass) {
				case IMM32:
					il.AddInstruction(il.Intrinsic({RegisterOrFlag::Register(dst)},
								ARM64_INTRIN_MSR,
								{il.Const(4, IMM(operand2))}));
					break;
				case REG:
					il.AddInstruction(il.Intrinsic({RegisterOrFlag::Register(dst)},
								ARM64_INTRIN_MSR,
								{ILREG(operand2)}));
					break;
				default:
					LogError("unknown MSR operand class: %x\n", operand2.operandClass);
					break;
			}
			break;
		}
	case ARM64_NEG:
	case ARM64_NEGS:
		il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1),
					il.Neg(REGSZ(operand1), ReadILOperand(il, instr.operands[1], REGSZ(operand1)), SETFLAGS)));
		break;
	case ARM64_NOP:
		il.AddInstruction(il.Nop());
		break;

	case ARM64_AUTDA:
	case ARM64_AUTDB:
	case ARM64_AUTIA:
	case ARM64_AUTIB:
	case ARM64_PACDA:
	case ARM64_PACDB:
	case ARM64_PACIA:
	case ARM64_PACIB:
		// <Xd> is address, <Xn> is modifier
		il.AddInstruction(il.Intrinsic({RegisterOrFlag::Register(REG(operand1))},
					operation_to_intrinsic(instr.operation),
					{ILREG(operand2)}));
		break;
	case ARM64_PACGA:
		// <Xd> is address, <Xn>, <Xm> are modifiers, keys
		il.AddInstruction(il.Intrinsic({RegisterOrFlag::Register(REG(operand1))},
					operation_to_intrinsic(instr.operation),
					{ILREG(operand2), ILREG(operand3)}));
		break;
	case ARM64_AUTIB1716:
	case ARM64_PACIA1716:
	case ARM64_PACIB1716:
		// x17 is address, x16 is modifier
		il.AddInstruction(il.Intrinsic({RegisterOrFlag::Register(REG_X17)},
					operation_to_intrinsic(instr.operation),
					{il.Register(8, REG_X16)}));
		break;
	case ARM64_AUTDZA:
	case ARM64_AUTDZB:
	case ARM64_AUTIZA:
	case ARM64_AUTIZB:
	case ARM64_PACDZA:
	case ARM64_PACDZB:
	case ARM64_PACIZA:
	case ARM64_PACIZB:
	case ARM64_XPACI:
	case ARM64_XPACD:
		// <Xd> is address, modifier is omitted or 0
		il.AddInstruction(il.Intrinsic({RegisterOrFlag::Register(REG(operand1))},
					operation_to_intrinsic(instr.operation),
					{}));
		break;
	case ARM64_AUTIBZ:
	case ARM64_PACIAZ:
	case ARM64_PACIBZ:
	case ARM64_XPACLRI:
		// x30 is address, modifier is omitted or 0
		il.AddInstruction(il.Intrinsic({RegisterOrFlag::Register(REG_X30)},
					operation_to_intrinsic(instr.operation),
					{}));
		break;
	case ARM64_AUTIBSP:
	case ARM64_PACIASP:
	case ARM64_PACIBSP:
		// x30 is address, sp is modifier
		il.AddInstruction(il.Intrinsic({RegisterOrFlag::Register(REG_X30)},
					operation_to_intrinsic(instr.operation),
					{il.Register(8, REG_SP)}));
		break;
	case ARM64_PRFUM:
	case ARM64_PRFM:
		// TODO use the PRFM types when we have a better option than defining 18 different intrinsics to account for:
		// - 3 types {PLD, PLI, PST}
		// - 3 targets {L1, L2, L3}
		// - 2 policies {KEEP, STM}
		il.AddInstruction(il.Intrinsic({}, ARM64_INTRIN_PRFM, {ReadILOperand(il, operand2, 8)}));
		break;
	case ARM64_ORN:
		il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1),
					il.Or(REGSZ(operand1),
						ILREG(operand2),
						il.Not(REGSZ(operand1), ReadILOperand(il, operand3, REGSZ(operand1))))));
		break;
	case ARM64_ORR:
	case ARM64_ORRS:
		il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1),
					il.Or(REGSZ(operand1),
						ILREG(operand2),
						ReadILOperand(il, operand3, REGSZ(operand1)), SETFLAGS)));
		break;
	case ARM64_PSB:
		il.AddInstruction(il.Intrinsic({}, ARM64_INTRIN_PSBCSYNC, {}));
		break;
	case ARM64_RET:
	case ARM64_RETAA:
	case ARM64_RETAB:
		il.AddInstruction(il.Return(il.Register(8, REG_X30)));
		break;
	case ARM64_REV:
		// if LLIL_BSWAP ever gets added, replace
		il.AddInstruction(il.Intrinsic({RegisterOrFlag::Register(REG(operand1))}, ARM64_INTRIN_REV, {ILREG(operand2)}));
		break;
	case ARM64_RBIT:
		il.AddInstruction(il.Intrinsic({RegisterOrFlag::Register(REG(operand1))}, ARM64_INTRIN_RBIT, {ILREG(operand2)}));
		break;
	case ARM64_ROR:
		il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1),
					il.RotateRight(REGSZ(operand2),
						ILREG(operand2),
						ReadILOperand(il, operand3, REGSZ(operand2)))));
		break;
	case ARM64_SBC:
	case ARM64_SBCS:
		il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1),
					il.SubBorrow(REGSZ(operand1),
						ILREG(operand2),
						ReadILOperand(il, operand3, REGSZ(operand1)),
						il.Not(0, il.Flag(IL_FLAG_C)),
						SETFLAGS)));
		break;
	case ARM64_SBFIZ:
		il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1),
						il.ArithShiftRight(REGSZ(operand1),
							il.ShiftLeft(REGSZ(operand1),
								ExtractBits(il, operand2, IMM(operand4), 0),
								il.Const(1, (REGSZ(operand1)*8)-IMM(operand4))),
							il.Const(1, (REGSZ(operand1)*8)-IMM(operand3)-IMM(operand4)))));
		break;
	case ARM64_SBFX:
		il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1),
						il.ArithShiftRight(REGSZ(operand1),
							il.ShiftLeft(REGSZ(operand1),
								ExtractBits(il, operand2, IMM(operand4), IMM(operand3)),
								il.Const(1, (REGSZ(operand1)*8)-IMM(operand4)-IMM(operand3))),
							il.Const(1, (REGSZ(operand1)*8)-IMM(operand4)))));
		break;
	case ARM64_SDIV:
		il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1),
					il.DivSigned(REGSZ(operand2), ILREG(operand2), ILREG(operand3))));
		break;
	case ARM64_SEV:
		il.AddInstruction(il.Intrinsic({}, ARM64_INTRIN_SEV, {}));
		break;
	case ARM64_SEVL:
		il.AddInstruction(il.Intrinsic({}, ARM64_INTRIN_SEVL, {}));
		break;
	case ARM64_SHL:
	{
		Register srcs[16], dsts[16];
		int dst_n = unpack_vector(operand1, dsts);
		int src_n = unpack_vector(operand2, srcs);

		if((dst_n != src_n) || dst_n==0)
			ABORT_LIFT;

		int rsize = get_register_size(dsts[0]);
		for(int i=0; i<dst_n; ++i) {
			il.AddInstruction(il.SetRegister(rsize, dsts[i],
				il.ShiftLeft(rsize, il.Register(rsize, srcs[i]), il.Const(0, IMM(operand3)))));
		}

		break;
	}
	case ARM64_STP:
		LoadStoreOperandPair(il, false, instr.operands[0], instr.operands[1], instr.operands[2]);
		break;
	case ARM64_STR:
	case ARM64_STUR:
		LoadStoreOperand(il, false, instr.operands[0], instr.operands[1]);
		break;
	case ARM64_STRB:
	case ARM64_STURB:
		LoadStoreOperandSize(il, false, false, 1, instr.operands[0], instr.operands[1]);
		break;
	case ARM64_STRH:
	case ARM64_STURH:
		LoadStoreOperandSize(il, false, false, 2, instr.operands[0], instr.operands[1]);
		break;
	case ARM64_SUB:
	case ARM64_SUBS:
		il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1),
					il.Sub(REGSZ(operand1), ILREG(operand2), ReadILOperand(il, instr.operands[2], REGSZ(operand1)),
					SETFLAGS)));
		break;
	case ARM64_SVC:
		il.AddInstruction(il.SetRegister(2, FAKEREG_SYSCALL_IMM, il.Const(2, IMM(operand1))));
		il.AddInstruction(il.SystemCall());
		break;
	case ARM64_SXTB:
		il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1),
					ExtractRegister(il, operand2, 0, 1, true, REGSZ(operand1))));
		break;
	case ARM64_SXTH:
		il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1),
					ExtractRegister(il, operand2, 0, 2, true, REGSZ(operand1))));
		break;
	case ARM64_SXTW:
		il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1),
					ExtractRegister(il, operand2, 0, 4, true, REGSZ(operand1))));
		break;
	case ARM64_TBNZ:
		ConditionalJump(arch, il,
			il.CompareNotEqual(REGSZ(operand1),
				ExtractBit(il, operand1, IMM(operand2)),
				il.Const(REGSZ(operand1), 0)),
			addrSize, IMM(operand3), addr + 4);
		return false;
	case ARM64_TBZ:
		ConditionalJump(arch, il,
			il.CompareEqual(REGSZ(operand1),
				ExtractBit(il, operand1, IMM(operand2)),
				il.Const(REGSZ(operand1), 0)),
			addrSize, IMM(operand3), addr + 4);
		return false;
	case ARM64_TST:
		il.AddInstruction(il.And(REGSZ(operand1),
						ILREG(operand1),
						ReadILOperand(il, operand2, REGSZ(operand1)), SETFLAGS));
		break;
	case ARM64_UMADDL:
		il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1),
					il.Add(REGSZ(operand1),
						ILREG(operand4),
						il.MultDoublePrecUnsigned(REGSZ(operand1), ILREG(operand2), ILREG(operand3)))));
		break;
	case ARM64_UMULL:
		il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1),
					il.MultDoublePrecUnsigned(REGSZ(operand1), ILREG(operand2), ILREG(operand3))));
		break;
	case ARM64_UMSUBL:
		il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1),
					il.Sub(REGSZ(operand1),
						ILREG(operand4),
						il.MultDoublePrecUnsigned(REGSZ(operand1), ILREG(operand2), ILREG(operand3)))));
		break;
	case ARM64_UMNEGL:
		il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1),
					il.Sub(REGSZ(operand1),
						il.Const(8, 0),
						il.MultDoublePrecUnsigned(REGSZ(operand1), ILREG(operand2), ILREG(operand3)))));
		break;
	case ARM64_SMADDL:
		il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1),
					il.Add(REGSZ(operand1),
						ILREG(operand4),
						il.MultDoublePrecSigned(REGSZ(operand1), ILREG(operand2), ILREG(operand3)))));
		break;
	case ARM64_USHR:
	{
		Register srcs[16], dsts[16];
		int dst_n = unpack_vector(operand1, dsts);
		int src_n = unpack_vector(operand2, srcs);

		if((dst_n != src_n) || dst_n==0)
			ABORT_LIFT;

		int rsize = get_register_size(dsts[0]);
		for(int i=0; i<dst_n; ++i) {
			il.AddInstruction(il.SetRegister(rsize, dsts[i],
				il.LogicalShiftRight(rsize, il.Register(rsize, srcs[i]), il.Const(0, IMM(operand3)))));
		}

		break;
	}
	case ARM64_SMULL:
		il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1),
					il.MultDoublePrecSigned(REGSZ(operand1), ILREG(operand2), ILREG(operand3))));
		break;
	case ARM64_SMSUBL:
		il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1),
					il.Sub(REGSZ(operand1),
						ILREG(operand4),
						il.MultDoublePrecSigned(REGSZ(operand1), ILREG(operand2), ILREG(operand3)))));
		break;
	case ARM64_SMNEGL:
		il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1),
					il.Sub(REGSZ(operand1),
						il.Const(8, 0),
						il.MultDoublePrecSigned(REGSZ(operand1), ILREG(operand2), ILREG(operand3)))));
		break;
	case ARM64_UMULH:
		il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1),
			il.LogicalShiftRight(16,
				il.MultDoublePrecUnsigned(REGSZ(operand1), ILREG(operand2), ILREG(operand3)),
				il.Const(1, 8))));
		break;
	case ARM64_SMULH:
		il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1),
			il.LogicalShiftRight(16,
				il.MultDoublePrecSigned(REGSZ(operand1), ILREG(operand2), ILREG(operand3)),
				il.Const(1, 8))));
		break;
	case ARM64_UDIV:
		il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1),
					il.DivUnsigned(REGSZ(operand2), ILREG(operand2), ILREG(operand3))));
		break;
	case ARM64_UBFIZ:
		il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1),
			il.ZeroExtend(REGSZ(operand1), il.ShiftLeft(REGSZ(operand2),
				il.And(REGSZ(operand2), ILREG(operand2), il.Const(REGSZ(operand2), (1LL << IMM(operand4)) - 1)),
					il.Const(1, IMM(operand3))))));
		break;
	case ARM64_UBFX:
	{
		// ubfx <dst>, <src>, <src_lsb>, <src_len>
		int src_lsb = IMM(operand3);
		int src_len = IMM(operand4);
		if(src_lsb==0 && (src_len==8 || src_len==16 || src_len==32 || src_len==64)) {
			il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1),
				il.LowPart(src_len/8, ILREG(operand2))));
		}
		else {
			il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1),
				il.ZeroExtend(REGSZ(operand1), il.And(REGSZ(operand2),
					il.LogicalShiftRight(REGSZ(operand2), ILREG(operand2), il.Const(1, IMM(operand3))),
						il.Const(REGSZ(operand2), (1LL << IMM(operand4)) - 1)))));
		}
		break;
	}
	case ARM64_UXTB:
		il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1),
					ExtractRegister(il, operand2, 0, 1, false, REGSZ(operand1))));
		break;
	case ARM64_UXTH:
		il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1),
					ExtractRegister(il, operand2, 0, 2, false, REGSZ(operand1))));
		break;
	case ARM64_WFE:
		il.AddInstruction(il.Intrinsic({}, ARM64_INTRIN_WFE, {}));
		break;
	case ARM64_WFI:
		il.AddInstruction(il.Intrinsic({}, ARM64_INTRIN_WFI, {}));
		break;
	case ARM64_BRK:
		il.AddInstruction(il.Trap(IMM(operand1))); // FIXME Breakpoint may need a parameter (IMM(operand1)));
		return false;
	case ARM64_DGH:
		il.AddInstruction(il.Intrinsic({}, ARM64_INTRIN_HINT_DGH, {}));
		break;
	case ARM64_TSB:
		il.AddInstruction(il.Intrinsic({}, ARM64_INTRIN_HINT_TSB, {}));
		break;
	case ARM64_CSDB:
		il.AddInstruction(il.Intrinsic({}, ARM64_INTRIN_HINT_CSDB, {}));
		break;
	case ARM64_HINT:
		if ((IMM(operand1) & ~0b110) == 0b100000)
			il.AddInstruction(il.Intrinsic({}, ARM64_INTRIN_HINT_BTI, {}));
		else
			LogWarn("unknown hint operand: 0x%" PRIx64 "\n", IMM(operand1));
		break;
	case ARM64_HLT:
		il.AddInstruction(il.Trap(IMM(operand1)));
		return false;

	case ARM64_YIELD:
		il.AddInstruction(il.Intrinsic({}, ARM64_INTRIN_YIELD, {}));
		break;
	default:
		il.AddInstruction(il.Unimplemented());
		break;
	}
	return true;
}

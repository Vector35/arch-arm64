#include <stdarg.h>
#include <cassert>
#include "lowlevelilinstruction.h"
#include "il.h"

using namespace BinaryNinja;
using namespace arm64;

#define IMM(X) X.immediate
#define REG(X) X.reg[0]
#define REGSZ(X) get_register_size((Register)REG(X))
#define ILREG(X) ExtractRegister(il, X, 0, REGSZ(X), false, REGSZ(X))
#define ILCONST(X) il.Const(REGSZ(X), IMM(X))
#define SETREG(R,V) il.AddInstruction(il.SetRegister(REGSZ(R), REG(R), V))
#define ADDREGOFS(R,O) il.Add(REGSZ(R), ILREG(R), il.Const(REGSZ(R), O))
#define ADDREGREG(R1,R2) il.Add(REGSZ(R1), ILREG(R1), ILREG(R2))
#define LOADVAL(R1, O) il.Load(REGSZ(R1), O)
#define LOADREG(R1) il.Load(REGSZ(R1), ILREG(R1))

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


static void ConditionExecute(LowLevelILFunction& il, Condition cond, ExprId trueCase, ExprId falseCase)
{
	LowLevelILLabel trueCode, falseCode, done;
	il.AddInstruction(il.If(GetCondition(il, cond), trueCode, falseCode));
	il.MarkLabel(trueCode);
	il.AddInstruction(trueCase);
	il.AddInstruction(il.Goto(done));
	il.MarkLabel(falseCode);
	il.AddInstruction(falseCase);
	il.AddInstruction(il.Goto(done));
	il.MarkLabel(done);
	return;
}


static ExprId GetILOperandMemoryAddress(LowLevelILFunction& il, InstructionOperand& operand, size_t offset, size_t addrSize)
{
	(void)offset;
	ExprId addr = 0;
	switch (operand.operandClass)
	{
	case MEM_REG:
		addr = il.Register(addrSize, operand.reg[0]);
		break;
	case MEM_PRE_IDX:
		break;
	case MEM_POST_IDX:
		break;
	case MEM_OFFSET:
		addr = il.Add(addrSize, il.Register(addrSize, operand.reg[0]), il.Const(addrSize, operand.immediate));
		break;
	case MEM_EXTENDED:
		if	(operand.shiftType == SHIFT_NONE)
			addr = il.Add(addrSize, il.Register(addrSize, operand.reg[0]), il.Const(addrSize, operand.immediate));
		else if (operand.shiftType == SHIFT_LSL)
			addr = il.Add(addrSize, il.Register(addrSize, operand.reg[0]),
					il.ShiftLeft(addrSize, il.Const(addrSize, operand.immediate), il.Const(addrSize, operand.shiftValue)));
		break;
	default:
		il.AddInstruction(il.Unimplemented());
		break;
	}
	return addr;
}


static ExprId ExtractRegister(LowLevelILFunction& il, InstructionOperand& operand, size_t regNum, size_t extractSize, bool signExtend, size_t resultSize)
{
	size_t opsz = get_register_size((Register)operand.reg[regNum]);

	switch (operand.reg[regNum]) {
		case REG_WZR:
		case REG_XZR:
			return il.Const(resultSize, 0);
		default:
			break;
	}

	ExprId res = il.Register(opsz, operand.reg[regNum]);

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


static ExprId GetShiftedRegister(LowLevelILFunction& il, InstructionOperand& operand, size_t regNum, size_t resultSize)
{
	ExprId res;

	switch (operand.shiftType)
	{
		case SHIFT_NONE:
		case SHIFT_LSR:
			res = ExtractRegister(il, operand, regNum, REGSZ(operand), false, resultSize);

			if (operand.shiftType == SHIFT_LSR && operand.shiftValue)
				res = il.LogicalShiftRight(resultSize, res,
						il.Const(1, operand.shiftValue));

			return res;
		case SHIFT_LSL:
			res = ExtractRegister(il, operand, regNum, REGSZ(operand), false, resultSize);
			break;
		case SHIFT_SXTB:
			res = ExtractRegister(il, operand, regNum, 1, true, resultSize);
			break;
		case SHIFT_SXTH:
			res = ExtractRegister(il, operand, regNum, 2, true, resultSize);
			break;
		case SHIFT_SXTW:
			res = ExtractRegister(il, operand, regNum, 4, true, resultSize);
			break;
		case SHIFT_SXTX:
			res = ExtractRegister(il, operand, regNum, 8, true, resultSize);
			break;
		case SHIFT_UXTB:
			res = ExtractRegister(il, operand, regNum, 1, false, resultSize);
			break;
		case SHIFT_UXTH:
			res = ExtractRegister(il, operand, regNum, 2, false, resultSize);
			break;
		case SHIFT_UXTW:
			res = ExtractRegister(il, operand, regNum, 4, false, resultSize);
			break;
		case SHIFT_UXTX:
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


static size_t ReadILOperand(LowLevelILFunction& il, InstructionOperand& operand, size_t resultSize)
{
	switch (operand.operandClass)
	{
	case IMM32:
	case IMM64:
		if (operand.shiftType != SHIFT_NONE && operand.shiftValue)
			return il.Const(resultSize, operand.immediate << operand.shiftValue);
		else
			return il.Const(resultSize, operand.immediate);
	case LABEL:
		return il.ConstPointer(8, operand.immediate);
	//case FIMM32:
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
		return il.Load(resultSize, GetILOperandMemoryAddress(il, operand, 0, resultSize));
	case MEM_PRE_IDX:
	case MEM_POST_IDX:
	case MULTI_REG:
	case FIMM32:
	case NONE:
	default:
		il.AddInstruction(il.Unimplemented());
		break;
	}

	return il.Unimplemented();
}


//ARMv8 has a lot of operations that store arrays of operands into a given dest operand
//This function given a dest operand and up to 4 source operands will emit the il for the instruction
static void LoadStoreOperandPair(
		LowLevelILFunction& il,
		bool load,
		InstructionOperand& operand1,
		InstructionOperand& operand2,
		InstructionOperand& operand3)
{
	ExprId tmp;
	if (load)
	{
		switch (operand3.operandClass)
		{
		case MEM_REG:
			//operand1.reg = [operand3.reg]
			SETREG(operand1, il.Operand(2, LOADREG(operand3)));
			//operand2.reg = [operand3.reg + operand1.size]
			SETREG(operand2, il.Operand(2, LOADVAL(operand3, ADDREGOFS(operand3, IMM(operand1)))));
			break;
		case MEM_OFFSET:
			//operand1.reg = [operand3.reg + operand3.imm]
			if (IMM(operand3) == 0)
				tmp = ILREG(operand3);
			else
				tmp = il.Add(REGSZ(operand3), ILREG(operand3), il.Const(REGSZ(operand3), IMM(operand3)));

			SETREG(operand1, il.Operand(2, il.Load(REGSZ(operand1), tmp)));

			if (IMM(operand3) == 0)
				tmp = il.Add(REGSZ(operand3), ILREG(operand3), il.Const(REGSZ(operand3), REGSZ(operand1)));
			else
				tmp = il.Add(REGSZ(operand3), ILREG(operand3), il.Const(REGSZ(operand3), IMM(operand3) + REGSZ(operand1)));
			//operand2.reg = [operand3.reg + operand3.imm + operand1.size]
			il.AddInstruction(il.SetRegister(REGSZ(operand2), REG(operand2),
					il.Operand(2, il.Load(REGSZ(operand1), tmp))));
			break;
		case MEM_PRE_IDX:
			//operand3.reg += operand3.imm
			if (IMM(operand3) != 0)
				SETREG(operand3, il.Add(REGSZ(operand3), ILREG(operand3), il.Const(REGSZ(operand3), IMM(operand3))));
			//operand1.reg = [operand3.reg]
			SETREG(operand1, il.Operand(2, il.Load(REGSZ(operand1), ILREG(operand3))));
			//operand2.reg = [operand3.reg + operand1.size]
			SETREG(operand2, il.Operand(2, il.Load(REGSZ(operand1),
							il.Add(REGSZ(operand1), il.Const(REGSZ(operand1), REGSZ(operand1)), ILREG(operand3)))));
			break;
		case MEM_POST_IDX:
			//operand1.reg = [operand3.reg]
			SETREG(operand1, il.Operand(2, il.Load(REGSZ(operand1), ILREG(operand3))));
			//operand2.reg = [operand3.reg + operand1.size]
			SETREG(operand2, il.Operand(2, il.Load(REGSZ(operand1),
						il.Add(REGSZ(operand1), il.Const(REGSZ(operand1), REGSZ(operand1)), ILREG(operand3)))));
			if (IMM(operand3) != 0)
			//operand3.reg += operand3.imm
				SETREG(operand3,
					il.Add(REGSZ(operand3), ILREG(operand3), il.Const(REGSZ(operand3), IMM(operand3))));
			break;
		default:
			il.AddInstruction(il.Unimplemented());
			break;
		}
	}
	else //store
	{
		switch (operand3.operandClass)
		{
		case MEM_REG:
			//[operand3.reg] = operand1.reg
			il.AddInstruction(il.Operand(2, il.Store(REGSZ(operand1), ILREG(operand3), ILREG(operand1))));
			//[operand3.reg + operand1.size] = operand2.reg
			il.AddInstruction(il.Operand(2,
					il.Store(REGSZ(operand2),
						il.Add(REGSZ(operand3),
							ILREG(operand3),
							il.Const(1, REGSZ(operand1))),
						ILREG(operand2))));
			break;
		case MEM_OFFSET:
			if (IMM(operand3) == 0)
				tmp = ILREG(operand3);
			else
				tmp = il.Add(REGSZ(operand3), ILREG(operand3), il.Const(REGSZ(operand3), IMM(operand3)));
			//[operand3.reg + operand3.immediate] = operand1.reg
			il.AddInstruction(il.Operand(2, il.Store(REGSZ(operand1), tmp, ILREG(operand1))));

			if (IMM(operand3) == 0)
				tmp = il.Add(REGSZ(operand3), ILREG(operand3), il.Const(REGSZ(operand3), REGSZ(operand1)));
			else
				tmp = il.Add(REGSZ(operand3), ILREG(operand3), il.Const(REGSZ(operand3), IMM(operand3) + REGSZ(operand1)));
			//[operand3.reg + operand3.immediate + operand1.size] = operand2.reg
			il.AddInstruction(il.Operand(2, il.Store(REGSZ(operand2), tmp, ILREG(operand2))));
			break;
		case MEM_PRE_IDX:
			//operand3.reg = operand3.reg + operand3.immediate
			if (IMM(operand3) != 0)
				il.AddInstruction(il.SetRegister(REGSZ(operand3), REG(operand3),
					il.Add(REGSZ(operand3),
						ILREG(operand3),
						il.Const(REGSZ(operand3), IMM(operand3)))));
			//[operand3.reg] = operand1.reg
			il.AddInstruction(il.Operand(2, il.Store(REGSZ(operand1), ILREG(operand3), ILREG(operand1))));
			//[operand3.reg + operand3.size] = operand2.reg
			il.AddInstruction(il.Operand(2,
					il.Store(REGSZ(operand2),
						il.Add(REGSZ(operand3),
							ILREG(operand3),
							il.Const(REGSZ(operand3), REGSZ(operand1))),
						ILREG(operand2))));
			break;
		case MEM_POST_IDX:
			//[operand3.reg] = operand1.reg
			il.AddInstruction(il.Operand(2, il.Store(REGSZ(operand1), ILREG(operand3), ILREG(operand1))));
			//[operand3.reg + operand3.size] = operand2.reg
			il.AddInstruction(il.Operand(2,
					il.Store(REGSZ(operand2),
						il.Add(REGSZ(operand3),
							ILREG(operand3),
							il.Const(REGSZ(operand3), REGSZ(operand1))),
						ILREG(operand2))));
			//operand3.reg = operand3.reg + operand3.immediate
			if (IMM(operand3) != 0)
				il.AddInstruction(il.SetRegister(REGSZ(operand3), REG(operand3),
					il.Add(REGSZ(operand3),
						ILREG(operand3),
						il.Const(REGSZ(operand3), IMM(operand3)))));
			break;
		default:
			il.AddInstruction(il.Unimplemented());
			break;
		}
	}
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


static ExprId Extract(LowLevelILFunction& il, InstructionOperand& reg, size_t nbits, size_t rightMostBit)
{
//Get N set bits at offset O
#define BITMASK(N,O) (((1LL << nbits) - 1) << O)
	return il.And(REGSZ(reg), ILREG(reg), il.Const(REGSZ(reg), BITMASK(nbits, rightMostBit)));
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


bool GetLowLevelILForInstruction(Architecture* arch, uint64_t addr, LowLevelILFunction& il, Instruction& instr, size_t addrSize)
{
	InstructionOperand& operand1 = instr.operands[0];
	InstructionOperand& operand2 = instr.operands[1];
	InstructionOperand& operand3 = instr.operands[2];
	InstructionOperand& operand4 = instr.operands[3];

	// these opcodes can't occur once aarch64_decompose() has been called
	assert(instr.operation != ARM64_UBFM);
	assert(instr.operation != ARM64_SBFM);

	LowLevelILLabel trueLabel, falseLabel;
	switch (instr.operation)
	{
	case ARM64_ADD:
	case ARM64_ADDS:
		il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1),
					il.Add(REGSZ(operand1),
						ILREG(operand2),
						ReadILOperand(il, operand3, REGSZ(operand1)),
						instr.operation == ARM64_ADDS ? IL_FLAGWRITE_ALL : 0)));
		break;
	case ARM64_AND:
	case ARM64_ANDS:
		il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1),
					il.And(REGSZ(operand1),
						ILREG(operand2),
						ReadILOperand(il, operand3, REGSZ(operand1)),
						instr.operation == ARM64_ANDS ? IL_FLAGWRITE_ALL : 0)));
		break;
	case ARM64_ADR:
	case ARM64_ADRP:
		il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1), il.ConstPointer(REGSZ(operand1), IMM(operand2))));
		break;
	case ARM64_ASR:
		il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1), il.ArithShiftRight(REGSZ(operand2), ILREG(operand2), il.Const(REGSZ(operand2), IMM(operand3)))));
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
	case ARM64_BR:
	case ARM64_BRAA:
	case ARM64_BRAAZ:
	case ARM64_BRAB:
	case ARM64_BRABZ:
		il.AddInstruction(il.Jump(ILREG(operand1)));
		return false;
	case ARM64_BIC:
		il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1),
					il.And(REGSZ(operand2),
						ILREG(operand2),
						il.Not(REGSZ(operand2),
							ReadILOperand(il, operand3, REGSZ(operand2)))
							)));
		break;
	case ARM64_BICS:
		il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1),
					il.And(REGSZ(operand2),
						ILREG(operand2),
						il.Not(REGSZ(operand2),
							ReadILOperand(il, operand3, REGSZ(operand2)), IL_FLAGWRITE_ALL)
							)));
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
					ReadILOperand(il, operand2, REGSZ(operand1)), IL_FLAGWRITE_ALL));
		break;
	case ARM64_CMP:
		il.AddInstruction(il.Sub(REGSZ(operand1),
					ILREG(operand1),
					ReadILOperand(il, operand2, REGSZ(operand1)), IL_FLAGWRITE_ALL));
		break;
	case ARM64_CCMP:
		{
			LowLevelILLabel trueCode, falseCode, done;

			il.AddInstruction(il.If(GetCondition(il, (Condition)REG(operand4)), trueCode, falseCode));

			il.MarkLabel(trueCode);
			il.AddInstruction(il.Sub(REGSZ(operand1),
						ILREG(operand1),
						ReadILOperand(il, operand2, REGSZ(operand1)), IL_FLAGWRITE_ALL));
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
		ConditionExecute(il, (Condition)REG(operand4),
			il.SetRegister(REGSZ(operand1), REG(operand1), ILREG(operand2)),
			il.SetRegister(REGSZ(operand1), REG(operand1), ILREG(operand3)));
		break;
	case ARM64_CSINC:
		ConditionExecute(il, (Condition)REG(operand4),
			il.SetRegister(REGSZ(operand1), REG(operand1), ILREG(operand2)),
			il.SetRegister(REGSZ(operand1), REG(operand1), il.Add(REGSZ(operand1), ILREG(operand3), il.Const(REGSZ(operand1), 1))));
		break;
	case ARM64_CSINV:
		ConditionExecute(il, (Condition)REG(operand4),
			il.SetRegister(REGSZ(operand1), REG(operand1), ILREG(operand2)),
			il.SetRegister(REGSZ(operand1), REG(operand1), il.Not(REGSZ(operand1), ILREG(operand3))));
		break;
	case ARM64_CSNEG:
		ConditionExecute(il, (Condition)REG(operand4),
			il.SetRegister(REGSZ(operand1), REG(operand1), ILREG(operand2)),
			il.SetRegister(REGSZ(operand1), REG(operand1), il.Neg(REGSZ(operand1), ILREG(operand3))));
		break;
	case ARM64_CSET:
		ConditionExecute(il, (Condition)REG(operand2),
			il.SetRegister(REGSZ(operand1), REG(operand1), il.Const(REGSZ(operand1), 1)),
			il.SetRegister(REGSZ(operand1), REG(operand1), il.Const(REGSZ(operand1), 0)));
		break;
	case ARM64_CSETM:
		ConditionExecute(il, (Condition)REG(operand2),
			il.SetRegister(REGSZ(operand1), REG(operand1), il.Const(REGSZ(operand1), -1)),
			il.SetRegister(REGSZ(operand1), REG(operand1), il.Const(REGSZ(operand1), 0)));
		break;
	case ARM64_CINC:
		ConditionExecute(il, (Condition)REG(operand3),
			il.SetRegister(REGSZ(operand1), REG(operand1), il.Add(REGSZ(operand1), ILREG(operand2), il.Const(REGSZ(operand1), 1))),
			il.SetRegister(REGSZ(operand1), REG(operand1), ILREG(operand2)));
		break;
	case ARM64_CINV:
		ConditionExecute(il, (Condition)REG(operand3),
			il.SetRegister(REGSZ(operand1), REG(operand1), il.Not(REGSZ(operand1), ILREG(operand2))),
			il.SetRegister(REGSZ(operand1), REG(operand1), ILREG(operand2)));
		break;
	case ARM64_CNEG:
		ConditionExecute(il, (Condition)REG(operand3),
			il.SetRegister(REGSZ(operand1), REG(operand1), il.Neg(REGSZ(operand1), ILREG(operand2))),
			il.SetRegister(REGSZ(operand1), REG(operand1), ILREG(operand2)));
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
		//No support for SIMD
		if (instr.operands[0].reg[0] >= REG_B0 && instr.operands[0].reg[0] <= REG_Q31)
			il.AddInstruction(il.Unimplemented());
		else
			LoadStoreOperandPair(il, true, instr.operands[0], instr.operands[1], instr.operands[2]);
		break;
	case ARM64_LDR:
	case ARM64_LDUR:
	case ARM64_LDRAA:
	case ARM64_LDRAB:
		//No support for SIMD
		if (instr.operands[0].reg[0] >= REG_B0 && instr.operands[0].reg[0] <= REG_Q31)
			il.AddInstruction(il.Unimplemented());
		else
			LoadStoreOperand(il, true, instr.operands[0], instr.operands[1]);
		break;
	case ARM64_LDRB:
	case ARM64_LDURB:
		if (instr.operands[0].reg[0] >= REG_B0 && instr.operands[0].reg[0] <= REG_Q31)
			il.AddInstruction(il.Unimplemented());
		else
			LoadStoreOperandSize(il, true, false, 1, instr.operands[0], instr.operands[1]);
		break;
	case ARM64_LDRH:
	case ARM64_LDURH:
		if (instr.operands[0].reg[0] >= REG_B0 && instr.operands[0].reg[0] <= REG_Q31)
			il.AddInstruction(il.Unimplemented());
		else
			LoadStoreOperandSize(il, true, false, 2, instr.operands[0], instr.operands[1]);
		break;
	case ARM64_LDRSB:
	case ARM64_LDURSB:
		if (instr.operands[0].reg[0] >= REG_B0 && instr.operands[0].reg[0] <= REG_Q31)
			il.AddInstruction(il.Unimplemented());
		else
			LoadStoreOperandSize(il, true, true, 1, instr.operands[0], instr.operands[1]);
		break;
	case ARM64_LDRSH:
	case ARM64_LDURSH:
		if (instr.operands[0].reg[0] >= REG_B0 && instr.operands[0].reg[0] <= REG_Q31)
			il.AddInstruction(il.Unimplemented());
		else
			LoadStoreOperandSize(il, true, true, 2, instr.operands[0], instr.operands[1]);
		break;
	case ARM64_LDRSW:
	case ARM64_LDURSW:
		if (instr.operands[0].reg[0] >= REG_B0 && instr.operands[0].reg[0] <= REG_Q31)
			il.AddInstruction(il.Unimplemented());
		else
			LoadStoreOperandSize(il, true, true, 4, instr.operands[0], instr.operands[1]);
		break;
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
		il.AddInstruction(il.Intrinsic({RegisterOrFlag::Register(REG(operand1))},
					ARM64_INTRIN_MRS,
					{ILREG(operand2)}));
		break;
	case ARM64_MSUB:
		il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1),
					il.Sub(REGSZ(operand1), ILREG(operand4), il.Mult(REGSZ(operand1), ILREG(operand2), ILREG(operand3)))));
		break;
	case ARM64_MSR:
		switch (operand2.operandClass) {
		case IMM32:
			il.AddInstruction(il.Intrinsic({RegisterOrFlag::Register(REG(operand1))},
						ARM64_INTRIN_MSR,
						{il.Const(4, IMM(operand2))}));
			break;
		case REG:
			il.AddInstruction(il.Intrinsic({RegisterOrFlag::Register(REG(operand1))},
						ARM64_INTRIN_MSR,
						{ILREG(operand2)}));
			break;
		default:
			LogError("unknown MSR operand class: %x\n", operand2.operandClass);
			break;
		}
		break;
	case ARM64_NEG:
		il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1),
					il.Neg(REGSZ(operand1), ReadILOperand(il, instr.operands[1], REGSZ(operand1)), IL_FLAGWRITE_ALL)));
		break;
	case ARM64_NOP:
		il.AddInstruction(il.Nop());
		break;
	case ARM64_ORN:
		il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1),
					il.Or(REGSZ(operand1),
						ILREG(operand2),
						il.Not(REGSZ(operand1), ReadILOperand(il, operand3, REGSZ(operand1))))));
		break;
	case ARM64_ORR:
		il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1),
					il.Or(REGSZ(operand1),
						ILREG(operand2),
						ReadILOperand(il, operand3, REGSZ(operand1)), IL_FLAGWRITE_ALL)));
		break;
	case ARM64_RET:
	case ARM64_RETAA:
	case ARM64_RETAB:
		il.AddInstruction(il.Return(il.Register(8, REG_X30)));
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
						il.Flag(IL_FLAG_C),
						instr.operation == ARM64_SBCS ? IL_FLAGWRITE_ALL : 0)));
		break;
	case ARM64_SBFX:
		il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1),
						il.ArithShiftRight(REGSZ(operand1),
							il.ShiftLeft(REGSZ(operand1),
								Extract(il, operand2, IMM(operand4), 0),
								il.Const(1, (REGSZ(operand1)*8)-IMM(operand4))),
							il.Const(1, (REGSZ(operand1)*8)-IMM(operand3)-IMM(operand4)))));
		break;
	case ARM64_SDIV:
		il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1),
					il.DivSigned(REGSZ(operand2), ILREG(operand2), ILREG(operand3))));
		break;
	case ARM64_SEV:
		il.AddInstruction(il.Intrinsic({}, ARM64_INTRIN_SEV, {}));
		break;
	case ARM64_STP:
		if (instr.operands[0].reg[0] >= REG_B0 && instr.operands[0].reg[0] <= REG_Q31)
			il.AddInstruction(il.Unimplemented());
		else
			LoadStoreOperandPair(il, false, instr.operands[0], instr.operands[1], instr.operands[2]);
		break;
	case ARM64_STR:
	case ARM64_STUR:
		if (instr.operands[0].reg[0] >= REG_B0 && instr.operands[0].reg[0] <= REG_Q31)
			il.AddInstruction(il.Unimplemented());
		else
			LoadStoreOperand(il, false, instr.operands[0], instr.operands[1]);
		break;
	case ARM64_STRB:
	case ARM64_STURB:
		if (instr.operands[0].reg[0] >= REG_B0 && instr.operands[0].reg[0] <= REG_Q31)
			il.AddInstruction(il.Unimplemented());
		else
			LoadStoreOperandSize(il, false, false, 1, instr.operands[0], instr.operands[1]);
		break;
	case ARM64_STRH:
	case ARM64_STURH:
		if (instr.operands[0].reg[0] >= REG_B0 && instr.operands[0].reg[0] <= REG_Q31)
			il.AddInstruction(il.Unimplemented());
		else
			LoadStoreOperandSize(il, false, false, 2, instr.operands[0], instr.operands[1]);
		break;
	case ARM64_SUB:
	case ARM64_SUBS:
		il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1),
					il.Sub(REGSZ(operand1), ILREG(operand2), ReadILOperand(il, instr.operands[2], REGSZ(operand1)),
					instr.operation == ARM64_SUBS ? IL_FLAGWRITE_ALL : 0)));
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
		ConditionalJump(arch, il, il.CompareNotEqual(REGSZ(operand1),
					Extract(il, operand1, 1, IMM(operand2)),
					il.Const(REGSZ(operand1), 0)),
				addrSize, IMM(operand3), addr + 4);
		return false;
	case ARM64_TBZ:
		ConditionalJump(arch, il, il.CompareEqual(REGSZ(operand1),
					Extract(il, operand1, 1, IMM(operand2)),
					il.Const(REGSZ(operand1), 0)),
				addrSize, IMM(operand3), addr + 4);
		return false;
	case ARM64_TST:
		il.AddInstruction(il.And(REGSZ(operand1),
						ILREG(operand1),
						ReadILOperand(il, operand2, REGSZ(operand1)), IL_FLAGWRITE_ALL));
		break;
	case ARM64_UMULL:
		il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1),
					il.MultDoublePrecUnsigned(REGSZ(operand1), ILREG(operand2), ILREG(operand3))));
		break;
	case ARM64_SMULL:
		il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1),
					il.MultDoublePrecSigned(REGSZ(operand1), ILREG(operand2), ILREG(operand3))));
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
		il.AddInstruction(il.SetRegister(REGSZ(operand1), REG(operand1),
			il.ZeroExtend(REGSZ(operand1), il.And(REGSZ(operand2),
				il.LogicalShiftRight(REGSZ(operand2), ILREG(operand2), il.Const(1, IMM(operand3))),
					il.Const(REGSZ(operand2), (1LL << IMM(operand4)) - 1)))));
		break;
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
	case ARM64_HINT:
		switch (IMM(operand1)) {
		case 0:
			il.AddInstruction(il.Intrinsic({}, ARM64_INTRIN_HINT_NOP, {}));
			break;
		case 1:
			il.AddInstruction(il.Intrinsic({}, ARM64_INTRIN_HINT_YIELD, {}));
			break;
		case 2:
			il.AddInstruction(il.Intrinsic({}, ARM64_INTRIN_HINT_WFE, {}));
			break;
		case 3:
			il.AddInstruction(il.Intrinsic({}, ARM64_INTRIN_HINT_WFI, {}));
			break;
		case 4:
			il.AddInstruction(il.Intrinsic({}, ARM64_INTRIN_HINT_SEV, {}));
			break;
		case 5:
			il.AddInstruction(il.Intrinsic({}, ARM64_INTRIN_HINT_SEVL, {}));
			break;
		case 6:
			il.AddInstruction(il.Intrinsic({}, ARM64_INTRIN_HINT_DGH, {}));
			break;
		case 0x10:
			il.AddInstruction(il.Intrinsic({}, ARM64_INTRIN_HINT_ESB, {}));
			break;
		case 0x11:
			il.AddInstruction(il.Intrinsic({}, ARM64_INTRIN_HINT_PSB, {}));
			break;
		case 0x12:
			il.AddInstruction(il.Intrinsic({}, ARM64_INTRIN_HINT_TSB, {}));
			break;
		case 0x14:
			il.AddInstruction(il.Intrinsic({}, ARM64_INTRIN_HINT_CSDB, {}));
			break;
		default:
			if ((IMM(operand1) & ~0b110) == 0b100000)
				il.AddInstruction(il.Intrinsic({}, ARM64_INTRIN_HINT_BTI, {}));
			else
				LogWarn("unknown hint operand: %llx\n", IMM(operand1));
			break;
		}

		break;
	case ARM64_HLT:
		il.AddInstruction(il.Trap(IMM(operand1)));
		return false;

	default:
		il.AddInstruction(il.Unimplemented());
		break;
	}
	return true;
}

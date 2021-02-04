#define IMM(X) X.immediate
#define REG(X) (X).reg[0]
#define REGSZ(X) get_register_size(REG(X))
#define ILREG(REGID) il.Register(get_register_size((REGID)), (REGID))
#define ILREG_X(X) ExtractRegister(il, X, 0, REGSZ(X), false, REGSZ(X)) /* ILREG with eXtract */
#define ILCONST(X) il.Const(REGSZ(X), IMM(X))
#define SETREG(R,V) il.AddInstruction(il.SetRegister(REGSZ(R), REG(R), V))
#define ADDREGOFS(R,O) il.Add(REGSZ(R), ILREG(R), il.Const(REGSZ(R), O))
#define ADDREGREG(R1,R2) il.Add(REGSZ(R1), ILREG(R1), ILREG(R2))
#define ONES(N) (-1ULL >> (64-N))
#define SETFLAGS (instr.setflags ? IL_FLAGWRITE_ALL : IL_FLAGWRITE_NONE)

#define IS_V_REG(R) ((R) >= REG_V0 && (R) <= REG_V31)
#define IS_ASIMD_OPERAND(O) ((O).operandClass==REG && IS_V_REG((O).reg[0]))
#define IS_Z_REG(R) ((R) >= REG_Z0 && (R) <= REG_Z31)
#define IS_P_REG(R) ((R) >= REG_P0 && (R) <= REG_P15)
#define IS_SVE_REG(R) (IS_Z_REG(R) || IS_P_REG(R))
#define IS_SVE_OPERAND(O) ((O).operandClass==REG && IS_SVE_REG((O).reg[0]))

#define ABORT_LIFT \
{ \
	il.AddInstruction(il.Unimplemented()); \
	break; \
}

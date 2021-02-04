/*
	generally:
	macros that end in "_O" operate on operands
	macros that start with "IL" construct BNIL expressions
*/

/* construct IL from a register id */
#define ILREG(R) il.Register(get_register_size((R)), (R))

/* helpers given a register id */
#define IS_V_REG(R) ((R) >= REG_V0 && (R) <= REG_V31)
#define IS_Z_REG(R) ((R) >= REG_Z0 && (R) <= REG_Z31)
#define IS_P_REG(R) ((R) >= REG_P0 && (R) <= REG_P15)
#define IS_SVE_REG(R) (IS_Z_REG(R) || IS_P_REG(R))

/* access stuff from operands */
#define IMM_O(O) (O).immediate
#define REG_O(O) (O).reg[0]
#define REGSZ_O(O) get_register_size(REG_O(O))

/* construct IL from an InstructionOperand */
#define ILREG_O(O) ExtractRegister(il, O, 0, REGSZ_O(O), false, REGSZ_O(O))
#define ILCONST_O(O) il.Const(REGSZ_O(O), IMM_O(O))

/* determine stuff from operands */
#define IS_ASIMD_O(O) ((O).operandClass==REG && IS_V_REG((O).reg[0]))
#define IS_SVE_O(O) ((O).operandClass==REG && IS_SVE_REG((O).reg[0]))

/* misc */
#define SETFLAGS (instr.setflags ? IL_FLAGWRITE_ALL : IL_FLAGWRITE_NONE)
#define ONES(N) (-1ULL >> (64-N))
#define ABORT_LIFT \
{ \
	il.AddInstruction(il.Unimplemented()); \
	break; \
}

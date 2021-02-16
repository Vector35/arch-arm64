#pragma once

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <string.h>

#include "operations.h"
#include "encodings_dec.h"
#include "regs.h"
#include "sysregs.h"

#ifdef _MSC_VER
#undef REG_NONE // collides with winnt's define
#endif

#ifdef __cplusplus
#define restrict __restrict
#endif

/* these are used in lookup tables elsewhere, modify with caution */
enum ArrangementSpec {
	ARRSPEC_NONE=0,

	ARRSPEC_FULL=1, /* 128-bit v-reg unsplit, eg: REG_V0_Q0 */

	/* 128 bit v-reg considered as... */
	ARRSPEC_2DOUBLES=2, /* (.2d) two 64-bit double-precision: REG_V0_D1, REG_V0_D0 */
	ARRSPEC_4SINGLES=3, /* (.4s) four 32-bit single-precision: REG_V0_S3, REG_V0_S2, REG_V0_S1, REG_V0_S0 */
	ARRSPEC_8HALVES=4, /* (.8h) eight 16-bit half-precision: REG_V0_H7, REG_V0_H6, (..., REG_V0_H0 */
	ARRSPEC_16BYTES=5, /* (.16b) sixteen 8-bit values: REG_V0_B15, REG_V0_B14, (..., REG_V0_B01 */

	/* low 64-bit of v-reg considered as... */
	ARRSPEC_1DOUBLE=6, /* (.d) one 64-bit double-precision: REG_V0_D0 */
	ARRSPEC_2SINGLES=7, /* (.2s) two 32-bit single-precision: REG_V0_S1, REG_V0_S0 */
	ARRSPEC_4HALVES=8, /* (.4h) four 16-bit half-precision: REG_V0_H3, REG_V0_H2, REG_V0_H1, REG_V0_H0 */
	ARRSPEC_8BYTES=9, /* (.8b) eight 8-bit values: REG_V0_B7, REG_V0_B6, (..., REG_V0_B0 */

	/* low 32-bit of v-reg considered as... */
	ARRSPEC_1SINGLE=10, /* (.s) one 32-bit single-precision: REG_V0_S0 */
	ARRSPEC_2HALVES=11, /* (.2h) two 16-bit half-precision: REG_V0_H1, REG_V0_H0 */
	ARRSPEC_4BYTES=12, /* (.4b) four 8-bit values: REG_V0_B3, REG_V0_B2, REG_V0_B1, REG_V0_B0 */

	/* low 16-bit of v-reg considered as... */
	ARRSPEC_1HALF=13, /* (.h) one 16-bit half-precision: REG_V0_H0 */

	/* low 8-bit of v-reg considered as... */
	ARRSPEC_1BYTE=14, /* (.b) one 8-bit byte: REG_V0_B0 */
};

//-----------------------------------------------------------------------------
// disassembly target features
//-----------------------------------------------------------------------------

/* see encodingindex.xml for strings like "arch_version="ARMv8.X-XXX" */
/* see also the HasXXX() functions in pcode */
#define ARCH_FEATURE_DGH ((uint64_t)1<<0) // added in ARMv8.0
#define ARCH_FEATURE_LOR ((uint64_t)1<<1) // added in ARMv8.1
#define ARCH_FEATURE_LSE ((uint64_t)1<<2) // added in ARMv8.1
#define ARCH_FEATURE_RDMA ((uint64_t)1<<3) // added in ARMv8.1
#define ARCH_FEATURE_BF16 ((uint64_t)1<<4) // added in ARMv8.2
#define ARCH_FEATURE_DotProd ((uint64_t)1<<5) // added in ARMv8.2
#define ARCH_FEATURE_FHM ((uint64_t)1<<6) // added in ARMv8.2
#define ARCH_FEATURE_FP16 ((uint64_t)1<<7) // added in ARMv8.2
#define ARCH_FEATURE_I8MM ((uint64_t)1<<8) // added in ARMv8.2
#define ARCH_FEATURE_SHA2 ((uint64_t)1<<9) // added in ARMv8.2
#define ARCH_FEATURE_SHA3 ((uint64_t)1<<10) // added in ARMv8.2
#define ARCH_FEATURE_SM3 ((uint64_t)1<<11) // added in ARMv8.2
#define ARCH_FEATURE_SM4 ((uint64_t)1<<12) // added in ARMv8.2
#define ARCH_FEATURE_CompNum ((uint64_t)1<<13) // added in ARMv8.3
#define ARCH_FEATURE_JConv ((uint64_t)1<<14) // added in ARMv8.3
#define ARCH_FEATURE_PAuth ((uint64_t)1<<15) // added in ARMv8.3
#define ARCH_FEATURE_RCPC ((uint64_t)1<<16) // added in ARMv8.3
#define ARCH_FEATURE_CondM ((uint64_t)1<<17) // added in ARMv8.4
#define ARCH_FEATURE_RCPC_84 ((uint64_t)1<<18) // added in ARMv8.4, corresponding to "ARMv8.4-RCPC" in spec
#define ARCH_FEATURE_Trace ((uint64_t)1<<19) // added in ARMv8.4
#define ARCH_FEATURE_BTI ((uint64_t)1<<20) // added in ARMv8.5, branch target identification
#define ARCH_FEATURE_CondM_85 ((uint64_t)1<<21) // added in ARMv8.5, corresponding to "ARMv8.5-CondM" in spec
#define ARCH_FEATURE_FRINT ((uint64_t)1<<22) // added in ARMv8.5
#define ARCH_FEATURE_MemTag ((uint64_t)1<<23) // added in ARMv8.5
#define ARCH_FEATURE_RAS ((uint64_t)1<<24) // ?
#define ARCH_FEATURE_SPE ((uint64_t)1<<25) // ?
#define ARCH_FEATURE_ARMv8_0 ((uint64_t)1<<26)
#define ARCH_FEATURE_ARMv8_1 ((uint64_t)1<<27)
#define ARCH_FEATURE_ARMv8_2 ((uint64_t)1<<28)
#define ARCH_FEATURE_ARMv8_3 ((uint64_t)1<<29)
#define ARCH_FEATURE_ARMv8_4 ((uint64_t)1<<30)
#define ARCH_FEATURE_ARMv8_5 ((uint64_t)1<<31)

/* see the HaveXXX() functions in pcode */
#define ARCH_FEATURE_AESExt ((uint64_t)1<<0)
#define ARCH_FEATURE_AtomicExt ((uint64_t)1<<1)
#define ARCH_FEATURE_BF16Ext ((uint64_t)1<<2)
#define ARCH_FEATURE_BTIExt ((uint64_t)1<<3)
#define ARCH_FEATURE_Bit128PMULLExt ((uint64_t)1<<4)
#define ARCH_FEATURE_CRCExt ((uint64_t)1<<5)
#define ARCH_FEATURE_DGHExt ((uint64_t)1<<6)
#define ARCH_FEATURE_DITExt ((uint64_t)1<<7)
#define ARCH_FEATURE_DOTPExt ((uint64_t)1<<8)
#define ARCH_FEATURE_FCADDExt ((uint64_t)1<<9)
#define ARCH_FEATURE_FJCVTZSExt ((uint64_t)1<<10)
#define ARCH_FEATURE_FP16Ext ((uint64_t)1<<11)
#define ARCH_FEATURE_FP16MulNoRoundingToFP32Ext ((uint64_t)1<<12)
#define ARCH_FEATURE_FlagFormatExt ((uint64_t)1<<13)
#define ARCH_FEATURE_FlagManipulateExt ((uint64_t)1<<14)
#define ARCH_FEATURE_FrintExt ((uint64_t)1<<15)
#define ARCH_FEATURE_Int8MatMulExt ((uint64_t)1<<16)
#define ARCH_FEATURE_MTEExt ((uint64_t)1<<17)
#define ARCH_FEATURE_PACExt ((uint64_t)1<<18)
#define ARCH_FEATURE_PANExt ((uint64_t)1<<19)
#define ARCH_FEATURE_QRDMLAHExt ((uint64_t)1<<20)
#define ARCH_FEATURE_RASExt ((uint64_t)1<<21)
#define ARCH_FEATURE_SBExt ((uint64_t)1<<22)
#define ARCH_FEATURE_SHA1Ext ((uint64_t)1<<23)
#define ARCH_FEATURE_SHA256Ext ((uint64_t)1<<24)
#define ARCH_FEATURE_SHA3Ext ((uint64_t)1<<25)
#define ARCH_FEATURE_SHA512Ext ((uint64_t)1<<26)
#define ARCH_FEATURE_SM3Ext ((uint64_t)1<<27)
#define ARCH_FEATURE_SM4Ext ((uint64_t)1<<28)
#define ARCH_FEATURE_SSBSExt ((uint64_t)1<<29)
#define ARCH_FEATURE_SVE ((uint64_t)1<<30)
#define ARCH_FEATURE_SVEFP32MatMulExt ((uint64_t)1<<31)
#define ARCH_FEATURE_SVEFP64MatMulExt ((uint64_t)1<<32)
#define ARCH_FEATURE_SelfHostedTrace ((uint64_t)1<<33)
#define ARCH_FEATURE_StatisticalProfiling ((uint64_t)1<<34)
#define ARCH_FEATURE_UAOExt ((uint64_t)1<<35)
#define ARCH_FEATURE_NVExt ((uint64_t)1<<36)
#define ARCH_FEATURE_VirtHostExt ((uint64_t)1<<37)
#define ARCH_FEATURE_TLBI ((uint64_t)1<<38) // ARMv8.4-TLBI, see tlbi_sys.html
#define ARCH_FEATURE_DCPoP ((uint64_t)1<<39) // ARMv8.2-DCPoP
#define ARCH_FEATURE_DCCVADP ((uint64_t)1<<40) // ARMv8.2-DCCVADP

#define ARCH_FEATURES_ALL 0xFFFFFFFFFFFFFFFF

//-----------------------------------------------------------------------------
// decode return values
//-----------------------------------------------------------------------------

#define DECODE_STATUS_OK 0 // success! the resulting named encoding is accurate
#define DECODE_STATUS_RESERVED -1 // spec says this space is reserved, eg: RESERVED_36_asisdsame
#define DECODE_STATUS_UNMATCHED -2 // decoding logic fell through the spec's checks
#define DECODE_STATUS_UNALLOCATED -3 // spec says this space is unallocated, eg: UNALLOCATED_10_branch_reg
#define DECODE_STATUS_UNDEFINED -4 // spec says this encoding is undefined, often due to a disallowed field
									// or a missing feature, eg: "if !HaveBF16Ext() then UNDEFINED;"
#define DECODE_STATUS_END_OF_INSTRUCTION -5 // spec decode EndOfInstruction(), instruction executes as NOP
#define DECODE_STATUS_LOST -6 // descended past a checks, ie: "SEE encoding_up_higher"
#define DECODE_STATUS_UNREACHABLE -7 // ran into pcode Unreachable()

//-----------------------------------------------------------------------------
// floating point condition register values
//-----------------------------------------------------------------------------

#define FPCR_AHP ((uint64_t)1 << 26)
#define FPCR_DN ((uint64_t)1 << 25)
#define FPCR_FZ ((uint64_t)1 << 24)
#define FPCR_RMode (uint64_t)0xC00000 // [23,22]
#define FPCR_Stride (uint64_t)0x300000 // [21,20]
#define FPCR_FZ16 ((uint64_t)1 << 19)
#define FPCR_Len (uint64_t)0x30000 // [18:16]
#define FPCR_IDE ((uint64_t)1 << 15)
#define FPCR_IXE ((uint64_t)1 << 12)
#define FPCR_UFE ((uint64_t)1 << 11)
#define FPCR_OFE ((uint64_t)1 << 10)
#define FPCR_DZE ((uint64_t)1 << 9)
#define FPCR_IOE ((uint64_t)1 << 8)

#define FPCR_GET_AHP(X) SLICE(X,26,26)
#define FPCR_GET_DN(X) SLICE(X,25,25)
#define FPCR_GET_FZ(X) SLICE(X,24,24)
#define FPCR_GET_RMode(X) SLICE(X,23,22)
#define FPCR_GET_Stride(X) SLICE(X,21,20)
#define FPCR_GET_FZ16(X) SLICE(X,19,19)
#define FPCR_GET_Len(X) SLICE(X,18,16)
#define FPCR_GET_IDE(X) SLICE(X,15,15)
#define FPCR_GET_IXE(X) SLICE(X,12,12)
#define FPCR_GET_UFE(X) SLICE(X,11,11)
#define FPCR_GET_OFE(X) SLICE(X,10,10)
#define FPCR_GET_DZE(X) SLICE(X,9,9)
#define FPCR_GET_IOE(X) SLICE(X,8,8)

//-----------------------------------------------------------------------------
// disassembly context (INPUT into disassembler)
//-----------------------------------------------------------------------------

typedef struct context_ {
	uint32_t insword;
	uint64_t address;
	uint64_t features0; // bitmask of ARCH_FEATURE_XXX
	uint64_t features1; // bitmask of ARCH_FEATURE_XXX
	//uint32_t exception_level; // used by AArch64.CheckSystemAccess()
	//uint32_t security_state;
	uint8_t pstate_btype; // used by BTypeCompatible_BTI()
	uint8_t pstate_el;
	uint8_t pstate_uao;
	bool BTypeCompatible;
	uint8_t BTypeNext;
	bool halted; // is CPU halted? used by Halted()
	uint64_t FPCR; // floating point control register
	bool EDSCR_HDE; // External Debug Status and Control Register, Halting debug enable

	/* specification scratchpad: ~300 possible named fields */
	uint64_t A;
	uint64_t ADD;
	uint64_t AccType_NORMAL;
	uint64_t AccType_STREAM;
	uint64_t AccType_UNPRIV;
	uint64_t AccType_VEC;
	uint64_t AccType_VECSTREAM;
	uint64_t B;
	uint64_t C;
	uint64_t CRm;
	uint64_t CRn;
	uint64_t D;
	uint64_t E;
	uint64_t H;
	uint64_t HCR_EL2_E2H, HCR_EL2_NV, HCR_EL2_NV1, HCR_EL2_TGE;
	uint64_t L;
	uint64_t LL;
	uint64_t M;
	uint64_t N;
	uint64_t O;
	uint64_t Op0, Op3;
	uint64_t P;
	uint64_t Pd, Pdm, Pdn, Pg, Pm, Pn, Pt;
	uint64_t Q, Qa, Qd, Qm, Qn, Qt, Qt2;
	uint64_t R, Ra, Rd, Rdn, Rm, Rmhi, Rn, Rs, Rt, Rt2;
	uint64_t S, Sa, Sd, Sm, Sn, St, St2;
	uint64_t S10;
	uint64_t SCTLR_EL1_UMA;
	uint64_t T;
	uint64_t U;
	uint64_t US;
	uint64_t V, Va, Vd, Vdn, Vm, Vn, Vt, Vt2;
	uint64_t W, Wa, Wd, Wdn, Wm, Wn, Ws, Wt, Wt2;
	uint64_t Xa, Xd, Xdn, Xm, Xn, Xs, Xt, Xt2;
	uint64_t Z, Za, Zd, Zda, Zdn, Zm, Zn, Zt;
	uint64_t a;
	uint64_t abs;
	uint64_t ac;
	uint64_t acc;
	uint64_t acctype;
	uint64_t accumulate;
	uint64_t amount;
	uint64_t and_test;
	uint64_t asimdimm;
	uint64_t b;
	uint64_t b40;
	uint64_t b5;
	uint64_t bit_pos;
	uint64_t bit_val;
	uint64_t branch_type;
	uint64_t c;
	uint64_t cmode;
	uint64_t cmp, cmph, cmpl, cmp_eq, cmp_with_zero;
	uint64_t comment;
	uint64_t comparison;
	uint64_t cond; /* careful! this is the pcode scratchpad .cond, NOT the .cond field of a struct InstructionOperand */
	uint64_t condition;
	uint64_t container_size;
	uint64_t containers;
	uint64_t countop;
	uint64_t crc32c;
	uint64_t csize;
	uint64_t d;
	uint64_t dtype, dtypeh, dtypel;
	uint64_t d_esize;
	uint64_t da;
	uint64_t data;
	uint64_t datasize;
	uint64_t decrypt;
	uint64_t destsize;
	uint64_t dm;
	uint64_t dn;
	uint64_t domain;
	uint64_t dst_index;
	uint64_t dst_unsigned;
	uint64_t dstsize;
	uint64_t e;
	uint64_t elements;
	uint64_t elements_per_container;
	uint64_t else_inc;
	uint64_t else_inv;
	uint64_t elsize;
	uint64_t eq;
	uint64_t esize;
	uint64_t exact;
	uint64_t extend;
	uint64_t extend_type;
	uint64_t f, ff;
	uint64_t field;
	uint64_t flags;
	uint64_t fltsize;
	uint64_t fpop;
	uint64_t fracbits;
	uint64_t ftype;
	uint64_t g;
	uint64_t h;
	uint64_t has_result;
	uint64_t hi;
	uint64_t hw;
	uint64_t i, i1, i2, i3h, i3l;
	uint64_t idxdsize;
	uint64_t imm;
	uint64_t imm1;
	uint64_t imm12;
	uint64_t imm13;
	uint64_t imm14;
	uint64_t imm16;
	uint64_t imm19;
	uint64_t imm2;
	uint64_t imm26;
	uint64_t imm3;
	uint64_t imm4;
	uint64_t imm5;
	uint64_t imm5b;
	uint64_t imm6;
	uint64_t imm64;
	uint64_t imm7;
	uint64_t imm8;
	uint64_t imm8h;
	uint64_t imm8l;
	uint64_t imm9;
	uint64_t imm9h;
	uint64_t imm9l;
	uint64_t immb;
	uint64_t immh;
	uint64_t immhi;
	uint64_t immlo;
	uint64_t immr;
	uint64_t imms;
	uint64_t index;
	uint64_t intsize;
	uint64_t int_U;
	uint64_t invert;
	uint64_t inzero;
	uint64_t isBefore;
	uint64_t is_tbl;
	uint64_t iszero;
	uint64_t ldacctype;
	uint64_t len;
	uint64_t level;
	uint64_t lsb;
	uint64_t lt;
	uint64_t m;
	uint64_t mask;
	uint64_t mbytes;
	uint64_t memop;
	uint64_t merging;
	uint64_t min;
	uint64_t minimum;
	uint64_t msb;
	uint64_t msize;
	uint64_t msz;
	uint64_t mulx_op;
	uint64_t n;
	uint64_t ne;
	uint64_t neg;
	uint64_t neg_i;
	uint64_t neg_r;
	uint64_t negated;
	uint64_t nreg;
	uint64_t nzcv;
	uint64_t o0, o1, o2, o3;
	uint64_t offs_size;
	uint64_t offs_unsigned;
	uint64_t offset;
	uint64_t op1_neg;
	uint64_t op1_unsigned;
	uint64_t op, op0, op1, op2, op3, op4, op21, op31, op54;
	uint64_t op2_unsigned;
	uint64_t op3_neg;
	uint64_t opa_neg;
	uint64_t opc;
	uint64_t opc2;
	uint64_t opcode, opcode2;
	uint64_t operand;
	uint64_t operation_;
	uint64_t opt, option;
	uint64_t osize;
	uint64_t pac;
	uint64_t page;
	uint64_t pair;
	uint64_t pairs;
	uint64_t part;
	uint64_t part1;
	uint64_t pat;
	uint64_t pattern;
	uint64_t poly;
	uint64_t pos;
	uint64_t position;
	uint64_t postindex;
	uint64_t pref_hint;
	uint64_t prfop;
	uint64_t ptype;
	uint64_t rd;
	uint64_t read;
	uint64_t regs;
	uint64_t regsize;
	uint64_t replicate;
	uint64_t rmode;
	uint64_t rot;
	uint64_t round;
	uint64_t rounding;
	uint64_t rpt;
	uint64_t rsize;
	uint64_t s;
	uint64_t s_esize;
	uint64_t saturating;
	uint64_t scale;
	uint64_t sel;
	uint64_t sel_a;
	uint64_t sel_b;
	uint64_t selem;
	uint64_t setflags;
	uint64_t sf;
	uint64_t sh;
	uint64_t shift;
	uint64_t shift_amount;
	uint64_t shift_type;
	uint64_t signal_all_nans;
	uint64_t signed_;
	uint64_t simm7;
	uint64_t size;
	uint64_t source_is_sp;
	uint64_t src_index;
	uint64_t src_unsigned;
	uint64_t srcsize;
	uint64_t ssize, ssz;
	uint64_t stacctype;
	uint64_t stream;
	uint64_t sub_i;
	uint64_t sub_op;
	uint64_t sub_r;
	uint64_t swsize;
	uint64_t sys_crm;
	uint64_t sys_crn;
	uint64_t sys_op0;
	uint64_t sys_op1;
	uint64_t sys_op2;
	uint64_t sz;
	uint64_t t;
	uint64_t t2;
	uint64_t tag_checked;
	uint64_t tag_offset;
	uint64_t target_level;
	uint64_t tmask;
	uint64_t tsize;
	uint64_t tsz;
	uint64_t tszh;
	uint64_t tszl;
	uint64_t types;
	uint64_t uimm4;
	uint64_t uimm6;
	uint64_t unpriv_at_el1;
	uint64_t unpriv_at_el2;
	uint64_t uns;
	uint64_t unsigned_;
	uint64_t use_key_a;
	uint64_t user_access_override;
	uint64_t wback;
	uint64_t wmask;
	uint64_t writeback;
	uint64_t xs;
	uint64_t zero_data;
} context;

//-----------------------------------------------------------------------------
// Instruction definition (OUTPUT from disassembler)
//-----------------------------------------------------------------------------

enum OperandClass {
	NONE = 0,
	IMM32,
	IMM64,
	FIMM32,
	STR_IMM,
	REG,
	MULTI_REG,
	SYS_REG,
	MEM_REG,
	MEM_PRE_IDX,
	MEM_POST_IDX,
	MEM_OFFSET,
	MEM_EXTENDED,
	LABEL,
	CONDITION,
	NAME,
	IMPLEMENTATION_SPECIFIC
};

enum Condition {
	COND_EQ, COND_NE, COND_CS, COND_CC,
	COND_MI, COND_PL, COND_VS, COND_VC,
	COND_HI, COND_LS, COND_GE, COND_LT,
	COND_GT, COND_LE, COND_AL, COND_NV,
	END_CONDITION
};

enum ShiftType {
	ShiftType_NONE, ShiftType_LSL, ShiftType_LSR, ShiftType_ASR,
	ShiftType_ROR, ShiftType_UXTW, ShiftType_SXTW, ShiftType_SXTX,
	ShiftType_UXTX, ShiftType_SXTB, ShiftType_SXTH, ShiftType_UXTH,
	ShiftType_UXTB, ShiftType_MSL, ShiftType_END,
};

enum Group {
	GROUP_UNALLOCATED,
	GROUP_DATA_PROCESSING_IMM,
	GROUP_BRANCH_EXCEPTION_SYSTEM,
	GROUP_LOAD_STORE,
	GROUP_DATA_PROCESSING_REG,
	GROUP_DATA_PROCESSING_SIMD,
	GROUP_DATA_PROCESSING_SIMD2,
	END_GROUP
};

#ifndef __cplusplus
	typedef enum SystemReg SystemReg;
	typedef enum OperandClass OperandClass;
	typedef enum Register Register;
	typedef enum Condition Condition;
	typedef enum ShiftType ShiftType;
	typedef enum FailureCodes FailureCodes;
	typedef enum Operation Operation;
	typedef enum Group Group;
	typedef enum ArrangementSpec ArrangementSpec;
#endif

#define MAX_REGISTERS 5
#define MAX_NAME 16

struct InstructionOperand {
	OperandClass operandClass;
	ArrangementSpec arrSpec;
	Register reg[MAX_REGISTERS];

	/* for class CONDITION */
	Condition cond;

	/* for class IMPLEMENTATION_SPECIFIC */
	uint8_t implspec[MAX_REGISTERS];

	/* for class SYS_REG */
	SystemReg sysreg;

	bool laneUsed;
	uint32_t lane;
	uint64_t immediate;
	ShiftType shiftType;
	bool shiftValueUsed;
	uint32_t shiftValue;
	ShiftType extend;
	bool signedImm;
	char pred_qual; // predicate register qualifier ('z' or 'm')
	bool mul_vl; // whether MEM_OFFSET has the offset "mul vl"

	/* for class NAME */
	char name[MAX_NAME];
};

#ifndef __cplusplus
	typedef struct InstructionOperand InstructionOperand;
#endif

#define MAX_OPERANDS 5

struct Instruction {
	uint32_t insword;
	enum ENCODING encoding;

	enum Operation operation;
	InstructionOperand operands[MAX_OPERANDS];

	bool setflags;
};

#ifndef __cplusplus
typedef struct Instruction Instruction;
#endif

#ifdef __cplusplus
extern "C" {
#endif

int aarch64_decompose(uint32_t instructionValue, Instruction *instr, uint64_t address);
size_t get_register_size(enum Register);

#ifdef __cplusplus
}
#endif


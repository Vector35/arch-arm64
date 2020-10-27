#!/usr/bin/env python

RET = b'\xc0\x03\x5f\xd6'

test_cases = [
	# ADDS_32S_addsub_ext
	# note: since the shift amount is 0, no LLIL_LSL need be generated
	(b'\x55\x01\x2B\x2B', 'LLIL_SET_REG.d(w21,LLIL_ADD.d(LLIL_REG.d(w10),LLIL_ZX.d(LLIL_LOW_PART.b(LLIL_REG.d(w11)))))'), # adds w21, w10, w11, uxtb
	(b'\xC5\xF2\x24\x2B', 'LLIL_SET_REG.d(w5,LLIL_ADD.d(LLIL_REG.d(w22),LLIL_LSL.d(LLIL_SX.d(LLIL_REG.d(w4)),LLIL_CONST.b(4))))'), # adds w5, w22, w4, sxtx #4
	(b'\x11\x29\x35\x2B', 'LLIL_SET_REG.d(w17,LLIL_ADD.d(LLIL_REG.d(w8),LLIL_LSL.d(LLIL_ZX.d(LLIL_LOW_PART.w(LLIL_REG.d(w21))),LLIL_CONST.b(2))))'), # adds w17, w8, w21, uxth #2
	(b'\x7E\x31\x3B\x2B', 'LLIL_SET_REG.d(w30,LLIL_ADD.d(LLIL_REG.d(w11),LLIL_LSL.d(LLIL_ZX.d(LLIL_LOW_PART.w(LLIL_REG.d(w27))),LLIL_CONST.b(4))))'), # adds w30, w11, w27, uxth #4
	# ADDS_64S_addsub_ext
	(b'\x13\x06\x22\xAB', 'LLIL_SET_REG.q(x19,LLIL_ADD.q(LLIL_REG.q(x16),LLIL_LSL.q(LLIL_ZX.q(LLIL_LOW_PART.b(LLIL_REG.d(w2))),LLIL_CONST.b(1))))'), # adds x19, x16, w2, uxtb #1
	(b'\xEF\x06\x21\xAB', 'LLIL_SET_REG.q(x15,LLIL_ADD.q(LLIL_REG.q(x23),LLIL_LSL.q(LLIL_ZX.q(LLIL_LOW_PART.b(LLIL_REG.d(w1))),LLIL_CONST.b(1))))'), # adds x15, x23, w1, uxtb #1
	(b'\xFA\xA5\x32\xAB', 'LLIL_SET_REG.q(x26,LLIL_ADD.q(LLIL_REG.q(x15),LLIL_LSL.q(LLIL_SX.q(LLIL_LOW_PART.w(LLIL_REG.d(w18))),LLIL_CONST.b(1))))'), # adds x26, x15, w18, sxth #1
	(b'\x00\x04\x20\xab', 'LLIL_SET_REG.q(x0,LLIL_ADD.q(LLIL_REG.q(x0),LLIL_LSL.q(LLIL_ZX.q(LLIL_LOW_PART.b(LLIL_REG.d(w0))),LLIL_CONST.b(1))))'), # adds x0, x0, w0, uxtb #0x1
	# note: if size(reg) == size(extend) then no extend (like LLIL_ZX) is needed
	(b'\x25\x6D\x2A\xAB', 'LLIL_SET_REG.q(x5,LLIL_ADD.q(LLIL_REG.q(x9),LLIL_LSL.q(LLIL_REG.q(x10),LLIL_CONST.b(3))))'), # adds x5, x9, x10, uxtx #3
	# ADD_32_addsub_ext
	(b'\xB0\x2F\x28\x0B', 'LLIL_SET_REG.d(w16,LLIL_ADD.d(LLIL_REG.d(w29),LLIL_LSL.d(LLIL_ZX.d(LLIL_LOW_PART.w(LLIL_REG.d(w8))),LLIL_CONST.b(3))))'), # add w16, w29, w8, uxth #3
	(b'\x4D\x73\x2B\x0B', 'LLIL_SET_REG.d(w13,LLIL_ADD.d(LLIL_REG.d(w26),LLIL_LSL.d(LLIL_ZX.d(LLIL_REG.d(w11)),LLIL_CONST.b(4))))'), # add w13, w26, w11, uxtx #4
	(b'\x07\xEE\x2E\x0B', 'LLIL_SET_REG.d(w7,LLIL_ADD.d(LLIL_REG.d(w16),LLIL_LSL.d(LLIL_SX.d(LLIL_REG.d(w14)),LLIL_CONST.b(3))))'), # add w7, w16, w14, sxtx #3
	(b'\x28\x63\x31\x0B', 'LLIL_SET_REG.d(w8,LLIL_ADD.d(LLIL_REG.d(w25),LLIL_ZX.d(LLIL_REG.d(w17))))'), # add w8, w25, w17, uxtx
	# ADD_64_addsub_ext
	(b'\xD2\xE8\x2B\x8B', 'LLIL_SET_REG.q(x18,LLIL_ADD.q(LLIL_REG.q(x6),LLIL_LSL.q(LLIL_REG.q(x11),LLIL_CONST.b(2))))'), # add x18, x6, x11, sxtx #2
	(b'\x5D\xC4\x2B\x8B', 'LLIL_SET_REG.q(x29,LLIL_ADD.q(LLIL_REG.q(x2),LLIL_LSL.q(LLIL_SX.q(LLIL_REG.d(w11)),LLIL_CONST.b(1))))'), # add x29, x2, w11, sxtw #1
	(b'\x82\x49\x31\x8B', 'LLIL_SET_REG.q(x2,LLIL_ADD.q(LLIL_REG.q(x12),LLIL_LSL.q(LLIL_ZX.q(LLIL_REG.d(w17)),LLIL_CONST.b(2))))'), # add x2, x12, w17, uxtw #2
	(b'\xFF\xA5\x2C\x8B', 'LLIL_SET_REG.q(sp,LLIL_ADD.q(LLIL_REG.q(x15),LLIL_LSL.q(LLIL_SX.q(LLIL_LOW_PART.w(LLIL_REG.d(w12))),LLIL_CONST.b(1))))'), # add sp, x15, w12, sxth #1
	# CMN_ADDS_32S_addsub_ext
	# Compare Negative (extended register) adds a register value and a sign or zero-extended register value, followed by an optional left shift amount.
	(b'\x7F\x8F\x2E\x2B', 'LLIL_ADD.d(LLIL_REG.d(w27),LLIL_LSL.d(LLIL_SX.d(LLIL_LOW_PART.b(LLIL_REG.d(w14))),LLIL_CONST.b(3)))'), # cmn w27, w14, sxtb #3
	(b'\x3F\x8E\x3E\x2B', 'LLIL_ADD.d(LLIL_REG.d(w17),LLIL_LSL.d(LLIL_SX.d(LLIL_LOW_PART.b(LLIL_REG.d(w30))),LLIL_CONST.b(3)))'), # cmn w17, w30, sxtb #3
	(b'\x3F\x83\x3D\x2B', 'LLIL_ADD.d(LLIL_REG.d(w25),LLIL_SX.d(LLIL_LOW_PART.b(LLIL_REG.d(w29))))'), # cmn w25, w29, sxtb
	(b'\x7F\x0F\x25\x2B', 'LLIL_ADD.d(LLIL_REG.d(w27),LLIL_LSL.d(LLIL_ZX.d(LLIL_LOW_PART.b(LLIL_REG.d(w5))),LLIL_CONST.b(3)))'), # cmn w27, w5, uxtb #3
	# CMN_ADDS_64S_addsub_ext
	(b'\xBF\x0D\x2D\xAB', 'LLIL_ADD.q(LLIL_REG.q(x13),LLIL_LSL.q(LLIL_ZX.q(LLIL_LOW_PART.b(LLIL_REG.d(w13))),LLIL_CONST.b(3)))'), # cmn x13, w13, uxtb #3
	(b'\x3F\x65\x22\xAB', 'LLIL_ADD.q(LLIL_REG.q(x9),LLIL_LSL.q(LLIL_REG.q(x2),LLIL_CONST.b(1)))'), # cmn x9, x2, uxtx #1
	# does the add to 0 get optimized out?
	(b'\xDF\xA8\x3F\xAB', 'LLIL_REG.q(x6)'), # cmn x6, wzr, sxth #2
	(b'\x3F\x8B\x3E\xAB', 'LLIL_ADD.q(LLIL_REG.q(x25),LLIL_LSL.q(LLIL_SX.q(LLIL_LOW_PART.b(LLIL_REG.d(w30))),LLIL_CONST.b(2)))'), # cmn x25, w30, sxtb #2
	# CMP_SUBS_32S_addsub_ext
	(b'\x1F\x2B\x2D\x6B', 'LLIL_SUB.d(LLIL_REG.d(w24),LLIL_LSL.d(LLIL_ZX.d(LLIL_LOW_PART.w(LLIL_REG.d(w13))),LLIL_CONST.b(2)))'), # cmp w24, w13, uxth #2
	(b'\xBF\x51\x23\x6B', 'LLIL_SUB.d(LLIL_REG.d(w13),LLIL_LSL.d(LLIL_REG.d(w3),LLIL_CONST.b(4)))'), # cmp w13, w3, uxtw #4
	(b'\x1F\xD0\x31\x6B', 'LLIL_SUB.d(LLIL_REG.d(w0),LLIL_LSL.d(LLIL_REG.d(w17),LLIL_CONST.b(4)))'), # cmp w0, w17, sxtw #4
	(b'\xBF\x53\x3E\x6B', 'LLIL_SUB.d(LLIL_REG.d(w29),LLIL_LSL.d(LLIL_REG.d(w30),LLIL_CONST.b(4)))'), # cmp w29, w30, uxtw #4
	# CMP_SUBS_64S_addsub_ext
	(b'\x3F\x49\x22\xEB', 'LLIL_SUB.q(LLIL_REG.q(x9),LLIL_LSL.q(LLIL_ZX.q(LLIL_REG.d(w2)),LLIL_CONST.b(2)))'), # cmp x9, w2, uxtw #2
	(b'\xDF\x93\x31\xEB', 'LLIL_SUB.q(LLIL_REG.q(x30),LLIL_LSL.q(LLIL_SX.q(LLIL_LOW_PART.b(LLIL_REG.d(w17))),LLIL_CONST.b(4)))'), # cmp x30, w17, sxtb #4
	(b'\x7F\x87\x27\xEB', 'LLIL_SUB.q(LLIL_REG.q(x27),LLIL_LSL.q(LLIL_SX.q(LLIL_LOW_PART.b(LLIL_REG.d(w7))),LLIL_CONST.b(1)))'), # cmp x27, w7, sxtb #1
	(b'\x9F\xEC\x34\xEB', 'LLIL_SUB.q(LLIL_REG.q(x4),LLIL_LSL.q(LLIL_REG.q(x20),LLIL_CONST.b(3)))'), # cmp x4, x20, sxtx #3
	# SUBS_32S_addsub_ext
	(b'\xCD\xC9\x38\x6B', 'LLIL_SET_REG.d(w13,LLIL_SUB.d(LLIL_REG.d(w14),LLIL_LSL.d(LLIL_REG.d(w24),LLIL_CONST.b(2))))'), # subs w13, w14, w24, sxtw #2
	(b'\x72\xF0\x2B\x6B', 'LLIL_SET_REG.d(w18,LLIL_SUB.d(LLIL_REG.d(w3),LLIL_LSL.d(LLIL_SX.d(LLIL_REG.d(w11)),LLIL_CONST.b(4))))'), # subs w18, w3, w11, sxtx #4
	(b'\x77\xC1\x23\x6B', 'LLIL_SET_REG.d(w23,LLIL_SUB.d(LLIL_REG.d(w11),LLIL_REG.d(w3)))'), # subs w23, w11, w3, sxtw
	(b'\xD4\x47\x3F\x6B', 'LLIL_SET_REG.d(w20,LLIL_REG.d(w30))'), # subs w20, w30, wzr, uxtw #1
	# SUBS_64S_addsub_ext
	(b'\x26\x44\x3C\xEB', 'LLIL_SET_REG.q(x6,LLIL_SUB.q(LLIL_REG.q(x1),LLIL_LSL.q(LLIL_ZX.q(LLIL_REG.d(w28)),LLIL_CONST.b(1))))'), # subs x6, x1, w28, uxtw #1
	(b'\x8A\xE2\x2E\xEB', 'LLIL_SET_REG.q(x10,LLIL_SUB.q(LLIL_REG.q(x20),LLIL_REG.q(x14)))'), # subs x10, x20, x14, sxtx
	(b'\xC2\x4B\x3A\xEB', 'LLIL_SET_REG.q(x2,LLIL_SUB.q(LLIL_REG.q(x30),LLIL_LSL.q(LLIL_ZX.q(LLIL_REG.d(w26)),LLIL_CONST.b(2))))'), # subs x2, x30, w26, uxtw #2
	(b'\x04\x4A\x20\xEB', 'LLIL_SET_REG.q(x4,LLIL_SUB.q(LLIL_REG.q(x16),LLIL_LSL.q(LLIL_ZX.q(LLIL_REG.d(w0)),LLIL_CONST.b(2))))'), # subs x4, x16, w0, uxtw #2
	# SUB_32_addsub_ext
	(b'\x9E\x82\x2C\x4B', 'LLIL_SET_REG.d(w30,LLIL_SUB.d(LLIL_REG.d(w20),LLIL_SX.d(LLIL_LOW_PART.b(LLIL_REG.d(w12)))))'), # sub w30, w20, w12, sxtb
	(b'\xB9\x42\x32\x4B', 'LLIL_SET_REG.d(w25,LLIL_SUB.d(LLIL_REG.d(w21),LLIL_REG.d(w18)))'), # sub w25, w21, w18, uxtw
	(b'\xD9\x66\x3C\x4B', 'LLIL_SET_REG.d(w25,LLIL_SUB.d(LLIL_REG.d(w22),LLIL_LSL.d(LLIL_ZX.d(LLIL_REG.d(w28)),LLIL_CONST.b(1))))'), # sub w25, w22, w28, uxtx #1
	(b'\xCD\x4F\x22\x4B', 'LLIL_SET_REG.d(w13,LLIL_SUB.d(LLIL_REG.d(w30),LLIL_LSL.d(LLIL_REG.d(w2),LLIL_CONST.b(3))))'), # sub w13, w30, w2, uxtw #3
	# SUB_64_addsub_ext
	(b'\xF7\x8D\x3F\xCB', 'LLIL_SET_REG.q(x23,LLIL_REG.q(x15))'), # sub x23, x15, wzr, sxtb #3
	(b'\xFF\x64\x27\xCB', 'LLIL_SET_REG.q(sp,LLIL_SUB.q(LLIL_REG.q(x7),LLIL_LSL.q(LLIL_REG.q(x7),LLIL_CONST.b(1))))'), # sub sp, x7, x7, lsl #1
	(b'\xA5\x23\x23\xCB', 'LLIL_SET_REG.q(x5,LLIL_SUB.q(LLIL_REG.q(x29),LLIL_ZX.q(LLIL_LOW_PART.w(LLIL_REG.d(w3)))))'), # sub x5, x29, w3, uxth
	(b'\xA4\x69\x37\xCB', 'LLIL_SET_REG.q(x4,LLIL_SUB.q(LLIL_REG.q(x13),LLIL_LSL.q(LLIL_REG.q(x23),LLIL_CONST.b(2))))'), # sub x4, x13, x23, uxtx #2
	(b'\x21\xf0\x9f\xf8', 'LLIL_INTRINSIC([],__prefetch,LLIL_CALL_PARAM([LLIL_LOAD.q(LLIL_ADD.q(LLIL_REG.q(x1),LLIL_CONST.q(-1)))]))'), # prfum pldl1strm, [x1, #-0x1]
	(b'\x21\x00\x80\xf9', 'LLIL_INTRINSIC([],__prefetch,LLIL_CALL_PARAM([LLIL_LOAD.q(LLIL_REG.q(x1))]))'), # prfm pldl1strm, [x1]
	(b'\x24\x98\x41\xba', 'LLIL_IF(LLIL_OR(LLIL_FLAG(z),LLIL_FLAG(c)),1,3); LLIL_ADD.q(LLIL_REG.q(x1),LLIL_CONST.q(1)); LLIL_GOTO(8); LLIL_SET_FLAG(n,LLIL_CONST(0)); LLIL_SET_FLAG(z,LLIL_CONST(1)); LLIL_SET_FLAG(c,LLIL_CONST(0)); LLIL_SET_FLAG(v,LLIL_CONST(0)); LLIL_GOTO(8)'), # ccmn x1, #0x1, #0x4, ls
	(b'\x41\x7c\xc3\x9b', 'LLIL_SET_REG.q(x1,LLIL_LSR.128(LLIL_MULU_DP.q(LLIL_REG.q(x2),LLIL_REG.q(x3)),LLIL_CONST.b(8)))'), # umulh x1, x2, x3
	(b'\x41\x7c\x43\x9b', 'LLIL_SET_REG.q(x1,LLIL_LSR.128(LLIL_MULS_DP.q(LLIL_REG.q(x2),LLIL_REG.q(x3)),LLIL_CONST.b(8)))'), # smulh x1, x2, x3
	(b'\x41\x7c\x23\x9b', 'LLIL_SET_REG.q(x1,LLIL_MULS_DP.q(LLIL_REG.d(w2),LLIL_REG.d(w3)))'), # smull x1, w2, w3
	(b'\x41\x7c\xa3\x9b', 'LLIL_SET_REG.q(x1,LLIL_MULU_DP.q(LLIL_REG.d(w2),LLIL_REG.d(w3)))'), # umull x1, w2, w3
	(b'\x41\x00\x03\x8b', 'LLIL_SET_REG.q(x1,LLIL_ADD.q(LLIL_REG.q(x2),LLIL_REG.q(x3)))'), # add x1,x2,x3
	(b'\x41\x00\x03\xab', 'LLIL_SET_REG.q(x1,LLIL_ADD.q(LLIL_REG.q(x2),LLIL_REG.q(x3)))'), # adds x1,x2,x3 with IL_FLAGWRITE_ALL
	(b'\x41\x00\x03\x8a', 'LLIL_SET_REG.q(x1,LLIL_AND.q(LLIL_REG.q(x2),LLIL_REG.q(x3)))'), # and x1,x2,x3
	(b'\x41\x00\x03\xea', 'LLIL_SET_REG.q(x1,LLIL_AND.q(LLIL_REG.q(x2),LLIL_REG.q(x3)))'), # ands x1,x2,x3 with IL_FLAGWRITE_ALL
	(b'\x41\x00\x03\xda', 'LLIL_SET_REG.q(x1,LLIL_SBB.q(LLIL_REG.q(x2),LLIL_REG.q(x3),LLIL_FLAG(c)))'), # sbc x1,x2,x3
	(b'\x41\x00\x03\xfa', 'LLIL_SET_REG.q(x1,LLIL_SBB.q(LLIL_REG.q(x2),LLIL_REG.q(x3),LLIL_FLAG(c)))'), # sbcs x1,x2,x3 with IL_FLAGWRITE_ALL
	(b'\x01\x00\x00\xd4', 'LLIL_SET_REG.w(syscall_imm,LLIL_CONST.w(0)); LLIL_SYSCALL()'), # svc #0; ret; ZwAccessCheck() on win-arm64
	(b'\x21\x00\x00\xd4', 'LLIL_SET_REG.w(syscall_imm,LLIL_CONST.w(1)); LLIL_SYSCALL()'), # svc #1; ret; ZwWorkerFactoryWorkerReady() on win-arm64
	(b'\x41\x00\x00\xd4', 'LLIL_SET_REG.w(syscall_imm,LLIL_CONST.w(2)); LLIL_SYSCALL()'), # svc #2; ret; ZwAcceptConnectPort() on win-arm64
	(b'\x61\x00\x00\xd4', 'LLIL_SET_REG.w(syscall_imm,LLIL_CONST.w(3)); LLIL_SYSCALL()'), # svc #3; ret; ZwMapUserPhysicalPagesScatter() on win-arm64
	(b'\xbf\x3f\x03\xd5', 'LLIL_INTRINSIC([],__dmb,LLIL_CALL_PARAM([]))'), # dmb sy (data memory barrier, system)
	(b'\xbf\x3e\x03\xd5', 'LLIL_INTRINSIC([],__dmb,LLIL_CALL_PARAM([]))'), # dmb st (data memory barrier, stores)
	(b'\xbf\x3a\x03\xd5', 'LLIL_INTRINSIC([],__dmb,LLIL_CALL_PARAM([]))'), # dmb ishst (data memory barrier, inner shareable domain)
	(b'\x9f\x3f\x03\xd5', 'LLIL_INTRINSIC([],__dsb,LLIL_CALL_PARAM([]))'), # dsb sy (data synchronization barrier, system)
	(b'\x9f\x3e\x03\xd5', 'LLIL_INTRINSIC([],__dsb,LLIL_CALL_PARAM([]))'), # dsb st (data synchronization barrier, stores)
	(b'\x9f\x3a\x03\xd5', 'LLIL_INTRINSIC([],__dsb,LLIL_CALL_PARAM([]))'), # dsb ishst (data synchronization barrier, inner shareable domain)
	(b'\xdf\x3f\x03\xd5', 'LLIL_INTRINSIC([],__isb,LLIL_CALL_PARAM([]))'), # isb (instruction synchronization barrier, implied system)
	(b'\x3f\x20\x03\xd5', 'LLIL_INTRINSIC([],__yield,LLIL_CALL_PARAM([]))'), # "yield" or "hint 0x1"
	(b'\x5f\x20\x03\xd5', 'LLIL_INTRINSIC([],__wfe,LLIL_CALL_PARAM([]))'), # "wfe" or "hint 0x2"
	(b'\x7f\x20\x03\xd5', 'LLIL_INTRINSIC([],__wfi,LLIL_CALL_PARAM([]))'), # "wfi" or "hint 0x3"
	(b'\x9f\x20\x03\xd5', 'LLIL_INTRINSIC([],__sev,LLIL_CALL_PARAM([]))'), # "hint 0x4" or "sev"
	(b'\xbf\x20\x03\xd5', 'LLIL_INTRINSIC([],__sevl,LLIL_CALL_PARAM([]))'), # "hint 0x5" or "sevl"
	(b'\xdf\x20\x03\xd5', 'LLIL_INTRINSIC([],SystemHintOp_DGH,LLIL_CALL_PARAM([]))'), # hint 0x6
	(b'\x1f\x22\x03\xd5', 'LLIL_INTRINSIC([],SystemHintOp_ESB,LLIL_CALL_PARAM([]))'), # hint 0x10
	(b'\x3f\x22\x03\xd5', 'LLIL_INTRINSIC([],SystemHintOp_PSB,LLIL_CALL_PARAM([]))'), # hint 0x11
	(b'\x5f\x22\x03\xd5', 'LLIL_INTRINSIC([],SystemHintOp_TSB,LLIL_CALL_PARAM([]))'), # hint 0x12
	(b'\x9f\x22\x03\xd5', 'LLIL_INTRINSIC([],SystemHintOp_CSDB,LLIL_CALL_PARAM([]))'), # hint 0x14
	(b'\x5f\x24\x03\xd5', 'LLIL_INTRINSIC([],SystemHintOp_BTI,LLIL_CALL_PARAM([]))'), # hint 0x22
	(b'\x00\xc0\x1e\xd5', 'LLIL_INTRINSIC([vbar_el3],_WriteStatusReg,LLIL_CALL_PARAM([LLIL_REG.q(x0)]))'), # msr vbar_el3, x0
	(b'\x00\x10\x1e\xd5', 'LLIL_INTRINSIC([sctlr_el3],_WriteStatusReg,LLIL_CALL_PARAM([LLIL_REG.q(x0)]))'), # msr sctlr_el3, x0
	(b'\xff\x44\x03\xd5', 'LLIL_INTRINSIC([daifclr],_WriteStatusReg,LLIL_CALL_PARAM([LLIL_CONST.d(4)]))'), # msr daifclr, #0x4
	(b'\x00\x10\x3e\xd5', 'LLIL_INTRINSIC([x0],_ReadStatusReg,LLIL_CALL_PARAM([LLIL_REG(sctlr_el3)]))'), # mrs x0, sctlr_el3
	(b'\xC1\x48\x52\x7A', 'LLIL_IF(LLIL_FLAG(n),1,3); LLIL_SUB.d(LLIL_REG.d(w6),LLIL_CONST.d(18)); LLIL_GOTO(8); LLIL_SET_FLAG(n,LLIL_CONST(0)); LLIL_SET_FLAG(z,LLIL_CONST(0)); LLIL_SET_FLAG(c,LLIL_CONST(0)); LLIL_SET_FLAG(v,LLIL_CONST(1)); LLIL_GOTO(8)'), # ccmp w6, #18, #1, mi
#	# this is funky: LLIL_SUB() is optmized away, and we needed it for the IL_FLAGWRITE_ALL, did it have effect?
	(b'\x62\x08\x40\x7A', 'LLIL_IF(LLIL_FLAG(z),1,3); LLIL_REG.d(w3); LLIL_GOTO(8); LLIL_SET_FLAG(n,LLIL_CONST(0)); LLIL_SET_FLAG(z,LLIL_CONST(0)); LLIL_SET_FLAG(c,LLIL_CONST(1)); LLIL_SET_FLAG(v,LLIL_CONST(0)); LLIL_GOTO(8)'), # ccmp w3, #0, #2, eq
	(b'\x43\xBA\x59\x7A', 'LLIL_IF(LLIL_CMP_NE(LLIL_FLAG(n),LLIL_FLAG(v)),1,3); LLIL_SUB.d(LLIL_REG.d(w18),LLIL_CONST.d(25)); LLIL_GOTO(8); LLIL_SET_FLAG(n,LLIL_CONST(0)); LLIL_SET_FLAG(z,LLIL_CONST(0)); LLIL_SET_FLAG(c,LLIL_CONST(1)); LLIL_SET_FLAG(v,LLIL_CONST(1)); LLIL_GOTO(8)'), # ccmp w18, #25, #3, lt
	(b'\xC4\x29\x5B\x7A', 'LLIL_IF(LLIL_NOT(LLIL_FLAG(c)),1,3); LLIL_SUB.d(LLIL_REG.d(w14),LLIL_CONST.d(27)); LLIL_GOTO(8); LLIL_SET_FLAG(n,LLIL_CONST(0)); LLIL_SET_FLAG(z,LLIL_CONST(1)); LLIL_SET_FLAG(c,LLIL_CONST(0)); LLIL_SET_FLAG(v,LLIL_CONST(0)); LLIL_GOTO(8)'), # ccmp w14, #27, #4, hs
	(b'\x24\x08\x5B\x7A', 'LLIL_IF(LLIL_FLAG(z),1,3); LLIL_SUB.d(LLIL_REG.d(w1),LLIL_CONST.d(27)); LLIL_GOTO(8); LLIL_SET_FLAG(n,LLIL_CONST(0)); LLIL_SET_FLAG(z,LLIL_CONST(1)); LLIL_SET_FLAG(c,LLIL_CONST(0)); LLIL_SET_FLAG(v,LLIL_CONST(0)); LLIL_GOTO(8)'), # ccmp w1, #27, #4, eq
	(b'\x22\x6A\x41\x7A', 'LLIL_IF(LLIL_FLAG(v),1,3); LLIL_SUB.d(LLIL_REG.d(w17),LLIL_CONST.d(1)); LLIL_GOTO(8); LLIL_SET_FLAG(n,LLIL_CONST(0)); LLIL_SET_FLAG(z,LLIL_CONST(0)); LLIL_SET_FLAG(c,LLIL_CONST(1)); LLIL_SET_FLAG(v,LLIL_CONST(0)); LLIL_GOTO(8)'), # ccmp w17, #1, #2, vs
	(b'\xA8\xA8\x41\x7A', 'LLIL_IF(LLIL_CMP_E(LLIL_FLAG(n),LLIL_FLAG(v)),1,3); LLIL_SUB.d(LLIL_REG.d(w5),LLIL_CONST.d(1)); LLIL_GOTO(8); LLIL_SET_FLAG(n,LLIL_CONST(1)); LLIL_SET_FLAG(z,LLIL_CONST(0)); LLIL_SET_FLAG(c,LLIL_CONST(0)); LLIL_SET_FLAG(v,LLIL_CONST(0)); LLIL_GOTO(8)'), # ccmp w5, #1, #8, ge
	(b'\x08\x49\x5E\x7A', 'LLIL_IF(LLIL_FLAG(n),1,3); LLIL_SUB.d(LLIL_REG.d(w8),LLIL_CONST.d(30)); LLIL_GOTO(8); LLIL_SET_FLAG(n,LLIL_CONST(1)); LLIL_SET_FLAG(z,LLIL_CONST(0)); LLIL_SET_FLAG(c,LLIL_CONST(0)); LLIL_SET_FLAG(v,LLIL_CONST(0)); LLIL_GOTO(8)'), # ccmp w8, #30, #8, mi
	(b'\x0a\x00\x80\x52', 'LLIL_SET_REG.d(w10,LLIL_CONST.d(0))'), # mov 10, #0
	(b'\x1f\x20\x03\xd5', ''), # nop, gets optimized from function
]

import sys
import binaryninja
from binaryninja import core
from binaryninja import binaryview
from binaryninja import lowlevelil

def il2str(il):
	if isinstance(il, lowlevelil.LowLevelILInstruction):
		lookup = {1:'.b', 2:'.w', 4:'.d', 8:'.q', 16:'.128'}
		size_suffix = lookup.get(il.size, '?') if il.size else ''
		return '%s%s(%s)' % (il.operation.name, size_suffix, ','.join([il2str(o) for o in il.operands]))
	elif isinstance(il, list):
		return '[' + ','.join([il2str(x) for x in il]) + ']'
	else:
		return str(il)

# TODO: make this less hacky
def instr_to_il(data):
	RETURN = b'\xc0\x03\x5f\xd6'

	platform = binaryninja.Platform['linux-aarch64']
	# make a pretend function that returns
	bv = binaryview.BinaryView.new(data + RETURN)
	bv.add_function(0, plat=platform)
	assert len(bv.functions) == 1

	result = []
	for block in bv.functions[0].low_level_il:
		for il in block:
			result.append(il2str(il))
	result = '; '.join(result)
	assert result.endswith('LLIL_RET(LLIL_REG.q(x30))'), \
			'%s didnt lift to function ending in ret, got: %s' % (data.hex(), result)
	result = result[0:result.index('LLIL_RET(LLIL_REG.q(x30))')]
	if result.endswith('; '):
		result = result[0:-2]

	return result

def test_all():
	for (test_i, (data, expected)) in enumerate(test_cases):
		actual = instr_to_il(data)
		if actual != expected:
			print('MISMATCH AT TEST %d!' % test_i)
			print('\t   input: %s' % data.hex())
			print('\texpected: %s' % expected)
			print('\t  actual: %s' % actual)
			return False

	return True

if __name__ == '__main__':
	if test_all():
		print('success!')
		sys.exit(0)
	else:
		sys.exit(-1)

if __name__ == 'arm64test':
	if test_all():
		print('success!')

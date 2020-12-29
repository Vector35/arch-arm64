#!/usr/bin/env python

RET = b'\xc0\x03\x5f\xd6'

test_cases = [
	(b'\x63\x06\xa3\x9b', 'LLIL_SET_REG.q(x3,LLIL_ADD.q(LLIL_REG.q(x1),LLIL_MULU_DP.q(LLIL_REG.d(w19),LLIL_REG.d(w3))))'), # umaddl  x3, w19, w3, x1
	(b'\x20\x00\x02\x9a', 'LLIL_SET_REG.q(x0,LLIL_ADC.q(LLIL_REG.q(x1),LLIL_REG.q(x2),LLIL_FLAG(c)))'), # adc x0, x1, x2
	(b'\x20\x00\x02\xba', 'LLIL_SET_REG.q(x0,LLIL_ADC.q(LLIL_REG.q(x1),LLIL_REG.q(x2),LLIL_FLAG(c)))'), # adcs x0, x1, x2
	(b'\x08\x75\x93\x13', 'LLIL_SET_REG.d(w8,LLIL_LSR.q(LLIL_OR.q(LLIL_LSL.q(LLIL_REG.d(w8),LLIL_CONST.b(0x20)),LLIL_REG.d(w19)),LLIL_CONST.b(0x1D)))'), # extr    w8, w8, w19, #0x1d
	(b'\x20\x28\xc2\x93', 'LLIL_SET_REG.q(x0,LLIL_LSR.128(LLIL_OR.128(LLIL_LSL.128(LLIL_REG.q(x1),LLIL_CONST.b(0x40)),LLIL_REG.q(x2)),LLIL_CONST.b(0xA)))'), # extr x0, x1, x2, #10
	(b'\xc6\x0c\xc0\xda', 'LLIL_INTRINSIC([x6],_byteswap,LLIL_CALL_PARAM([LLIL_REG.q(x6)]))'), # rev x6, x6
	(b'\xcb\x10\xc0\xda', 'LLIL_INTRINSIC([x11],_CountLeadingZeros,LLIL_CALL_PARAM([LLIL_REG.q(x6)]))'), # clz     x11, x6
	(b'\x63\x00\xc0\xda', 'LLIL_INTRINSIC([x3],__rbit,LLIL_CALL_PARAM([LLIL_REG.q(x3)]))'), # rbit    x3, x3
	# Unknown system register
	(b'\x21\x00\x1b\xd5', 'LLIL_INTRINSIC([unknown_catchall],_WriteStatusReg,LLIL_CALL_PARAM([LLIL_REG.q(x1)]))'), # msr s3_3_c0_c0_1, x1
	(b'\x23\x00\x3b\xd5', 'LLIL_INTRINSIC([x3],_ReadStatusReg,LLIL_CALL_PARAM([LLIL_REG.d(unknown_catchall)]))'), # mrs x3, s3_3_c0_c0_1
	(b'\xe0\x03\x9f\xd6', 'LLIL_INTRINSIC([],_eret,LLIL_CALL_PARAM([])); LLIL_TRAP(0)'), # eret
	(b'\x00\x10\x2e\x1e', 'LLIL_SET_REG.d(s0,LLIL_FLOAT_CONST.d(1.0))'), # fmov s0, #1.00000000
	(b'\x01\x10\x20\x1e', 'LLIL_SET_REG.d(s1,LLIL_FLOAT_CONST.d(2.0))'), # fmov s1, #2.00000000
	(b'\x00\x28\x21\x1e', 'LLIL_SET_REG.d(s0,LLIL_FADD.d(LLIL_REG.d(s0),LLIL_REG.d(s1)))'), # fadd s0, s0, s1
	(b'\x00\x38\x21\x1e', 'LLIL_SET_REG.d(s0,LLIL_FSUB.d(LLIL_REG.d(s0),LLIL_REG.d(s1)))'), # fsub s0, s0, s1
	(b'\x00\x08\x21\x1e', 'LLIL_SET_REG.d(s0,LLIL_FMUL.d(LLIL_REG.d(s0),LLIL_REG.d(s1)))'), # fmul s0, s0, s1
	(b'\x00\x18\x21\x1e', 'LLIL_SET_REG.d(s0,LLIL_FDIV.d(LLIL_REG.d(s0),LLIL_REG.d(s1)))'), # fdiv s0, s0, s1
	(b'\xe0\x0f\x40\xbd', 'LLIL_SET_REG.d(s0,LLIL_LOAD.d(LLIL_ADD.q(LLIL_REG.q(sp),LLIL_CONST.q(0xC))))'), # ldr s0, [sp, #0xc]
	(b'\xe1\x0b\x40\xbd', 'LLIL_SET_REG.d(s1,LLIL_LOAD.d(LLIL_ADD.q(LLIL_REG.q(sp),LLIL_CONST.q(0x8))))'), # ldr s1, [sp, #0x8]
	(b'\x29\x7d\x40\xd3', 'LLIL_SET_REG.q(x9,LLIL_LOW_PART.d(LLIL_REG.q(x9)))'), # ubfx x9, x9, #0, #0x20
	# FMOV_32H_float2int 0001111011100110000000xxxxxxxxxx (half-precision to 32-bit)
	(b'\x22\x02\xE6\x1E', 'LLIL_SET_REG.d(w2,LLIL_FLOAT_TO_INT.d(LLIL_REG.w(h17)))'), # fmov w2, h17
	(b'\x98\x02\xE6\x1E', 'LLIL_SET_REG.d(w24,LLIL_FLOAT_TO_INT.d(LLIL_REG.w(h20)))'), # fmov w24, h20
	# FMOV_32S_float2int 0001111000100110000000xxxxxxxxxx (single-precision to 32-bit)
	(b'\xEA\x02\x26\x1E', 'LLIL_SET_REG.d(w10,LLIL_FLOAT_TO_INT.d(LLIL_REG.d(s23)))'), # fmov w10, s23
	(b'\xEC\x02\x26\x1E', 'LLIL_SET_REG.d(w12,LLIL_FLOAT_TO_INT.d(LLIL_REG.d(s23)))'), # fmov w12, s23
	# FMOV_64D_float2int 1001111001100110000000xxxxxxxxxx (double-precision to 64-bit)
	(b'\xF9\x03\x66\x9E', 'LLIL_SET_REG.q(x25,LLIL_FLOAT_TO_INT.q(LLIL_REG.q(d31)))'), # fmov x25, d31
	(b'\x15\x03\x66\x9E', 'LLIL_SET_REG.q(x21,LLIL_FLOAT_TO_INT.q(LLIL_REG.q(d24)))'), # fmov x21, d24
	# FMOV_64H_float2int 1001111011100110000000xxxxxxxxxx (half-precision to 64-bit)
	(b'\x7A\x01\xE6\x9E', 'LLIL_SET_REG.q(x26,LLIL_FLOAT_TO_INT.q(LLIL_REG.w(h11)))'), # fmov x26, h11
	(b'\x75\x00\xE6\x9E', 'LLIL_SET_REG.q(x21,LLIL_FLOAT_TO_INT.q(LLIL_REG.w(h3)))'), # fmov x21, h3
	# FMOV_64VX_float2int 1001111010101110000000xxxxxxxxxx
	#b'\x84\x03\xAE\x9E', '?'), # fmov x4, v28.d[1]
	#b'\x07\x01\xAE\x9E', '?'), # fmov x7, v8.d[1]
	# FMOV_D64_float2int 1001111001100111000000xxxxxxxxxx
	(b'\x13\x00\x67\x9E', 'LLIL_SET_REG.q(d19,LLIL_FLOAT_TO_INT.q(LLIL_REG.q(x0)))'), # fmov d19, x0
	(b'\xA8\x02\x67\x9E', 'LLIL_SET_REG.q(d8,LLIL_FLOAT_TO_INT.q(LLIL_REG.q(x21)))'), # fmov d8, x21
	# FMOV_D_floatdp1 0001111001100000010000xxxxxxxxxx
	#(b'\x78\x43\x60\x1E', '?'), # fmov d24, d27
	#(b'\x73\x42\x60\x1E', '?'), # fmov d19, d19
	# FMOV_D_floatimm 00011110011xxxxxxxx10000000xxxxx
	#(b'\x11\xF0\x7F\x1E', '?'), # fmov d17, #-1.9375
	#(b'\x13\x30\x71\x1E', '?'), # fmov d19, #-3.125
	# FMOV_H32_float2int 0001111011100111000000xxxxxxxxxx
	(b'\x7C\x02\xE7\x1E', 'LLIL_SET_REG.w(h28,LLIL_FLOAT_TO_INT.w(LLIL_REG.d(w19)))'), # fmov h28, w19
	(b'\xA2\x00\xE7\x1E', 'LLIL_SET_REG.w(h2,LLIL_FLOAT_TO_INT.w(LLIL_REG.d(w5)))'), # fmov h2, w5
	# FMOV_H64_float2int 1001111011100111000000xxxxxxxxxx
	(b'\xCA\x01\xE7\x9E', 'LLIL_SET_REG.w(h10,LLIL_FLOAT_TO_INT.w(LLIL_REG.q(x14)))'), # fmov h10, x14
	(b'\xA9\x03\xE7\x9E', 'LLIL_SET_REG.w(h9,LLIL_FLOAT_TO_INT.w(LLIL_REG.q(x29)))'), # fmov h9, x29
	# FMOV_S32_float2int 0001111000100111000000xxxxxxxxxx
	(b'\x51\x00\x27\x1E', 'LLIL_SET_REG.d(s17,LLIL_FLOAT_TO_INT.d(LLIL_REG.d(w2)))'), # fmov s17, w2
	(b'\xE1\x03\x27\x1E', 'LLIL_SET_REG.d(s1,LLIL_FLOAT_TO_INT.d(LLIL_CONST.d(0x0)))'), # fmov s1, wzr
	# FMOV_V64I_float2int 1001111010101111000000xxxxxxxxxx
	#b'\x4E\x03\xAF\x9E', '?'), # fmov v14.d[1], x26
	#b'\xDC\x01\xAF\x9E', '?'), # fmov v28.d[1], x14
	# FMOV_H_floatdp1 0001111011100000010000xxxxxxxxxx
	#b'\xE6\x42\xE0\x1E', '?'), # fmov h6, h23
	#b'\x86\x43\xE0\x1E', '?'), # fmov h6, h28
	# FMOV_H_floatimm 00011110111xxxxxxxx10000000xxxxx
	#b'\x17\xB0\xF2\x1E', '?'), # fmov h23, #-5.25
	#b'\x19\xD0\xE4\x1E', '?'), # fmov h25, #11.0
	# FMOV_S_floatdp1 0001111000100000010000xxxxxxxxxx
	#b'\x64\x41\x20\x1E', '?'), # fmov s4, s11
	#b'\x57\x40\x20\x1E', '?'), # fmov s23, s2
	# FMOV_S_floatimm 00011110001xxxxxxxx10000000xxxxx
	#b'\x11\x10\x3F\x1E', '?'), # fmov s17, #-1.5
	#b'\x0E\xB0\x26\x1E', '?'), # fmov s14, #21.0
	# FMOV_asimdimm_D2_d 0110111100000xxx1111xxxxxxxxxxxx
	#b'\x0D\xF5\x04\x6F', '?'), # fmov v13.2d, #-3.0
	#b'\xD8\xF6\x05\x6F', '?'), # fmov v24.2d, #-22.0
	# FMOV_asimdimm_H_h 0x00111100000xxx111111xxxxxxxxxx
	#b'\x7D\xFD\x01\x0F', '?'), # fmov v29.4h, #13.5
	#b'\x30\xFD\x06\x4F', '?'), # fmov v16.8h, #-0.1953125
	# FMOV_asimdimm_S_s 0x00111100000xxx111101xxxxxxxxxx
	#b'\x37\xF7\x04\x0F', '?'), # fmov v23.2s, #-6.25
	#b'\x0D\xF4\x04\x0F', '?'), # fmov v13.2s, #-2.0
	# FMOV_fcpy_z_p_i_ 00000101xx01xxxx110xxxxxxxxxxxxx
	#b'\xDB\xCD\xD0\x05', '?'), # fmov z27.d, p0/m, #0.9375
	#b'\x2F\xDA\x94\x05', '?'), # fmov z15.s, p4/m, #-0.265625
	# FMOV_fdup_z_i_ 00100101xx111001110xxxxxxxxxxxxx
	#b'\xA8\xD7\xF9\x25', '?'), # fmov z8.d, #-29.0
	#b'\xD0\xD1\xF9\x25', '?'), # fmov z16.d, #-3.75
	(b'\x00\xc0\x1e\xd5', 'LLIL_INTRINSIC([vbar_el3],_WriteStatusReg,LLIL_CALL_PARAM([LLIL_REG.q(x0)]))'), # msr vbar_el3, x0
	(b'\x69\x01\x08\x4a', 'LLIL_SET_REG.d(w9,LLIL_XOR.d(LLIL_REG.d(w11),LLIL_REG.d(w8)))'), # eor w9, w11, w8
	(b'\x2c\x09\xd5\x4a', 'LLIL_SET_REG.d(w12,LLIL_XOR.d(LLIL_REG.d(w9),LLIL_ROR.d(LLIL_REG.d(w21),LLIL_CONST.b(0x2))))'), # eor w12, w9, w21, ror #0x2
	# adrp
	(b'\x80\x00\x00\xb0', 'LLIL_SET_REG.q(x0,LLIL_CONST.q(0x11000))'), # adrp x0, 0x11000
	# compare with asr
	(b'\x5f\x0d\x88\xeb', 'LLIL_SUB.q(LLIL_REG.q(x10),LLIL_ASR.q(LLIL_REG.q(x8),LLIL_CONST(3)))'), # cmp x10, x8, asr #0x3
	(b'\x1f\x0c\x81\xeb', 'LLIL_SUB.q(LLIL_REG.q(x0),LLIL_ASR.q(LLIL_REG.q(x1),LLIL_CONST(3)))'), # cmp x0, x1, asr #0x3
	(b'\x1f\x04\x81\x6b', 'LLIL_SUB.d(LLIL_REG.d(w0),LLIL_ASR.d(LLIL_REG.d(w1),LLIL_CONST(1)))'), # cmp w0, w1, asr #0x1
	(b'\x3f\x14\x82\x6b', 'LLIL_SUB.d(LLIL_REG.d(w1),LLIL_ASR.d(LLIL_REG.d(w2),LLIL_CONST(5)))'), # cmp w1, w2, asr #0x5
	# bfi/bfc/bfxil aliases of bfm
	# BFC_BFM_32M_bitfield 0011001100xxxxxxxxxxxxxxxxxxxxxx
	(b'\xF5\x27\x1F\x33', 'LLIL_SET_REG.d(w21,LLIL_AND.d(LLIL_CONST.d(0xFFFFF801),LLIL_REG.d(w21)))'), # bfc w21, #1, #10
	(b'\xFF\x37\x16\x33', 'LLIL_SET_REG.d(wzr,LLIL_CONST.d(0x0))'), # bfc wzr, #10, #14 (optimized: any BFC on WZR yields 0)
	(b'\xF0\x2B\x17\x33', 'LLIL_SET_REG.d(w16,LLIL_AND.d(LLIL_CONST.d(0xFFF001FF),LLIL_REG.d(w16)))'), # bfc w16, #9, #11
	(b'\xEE\x5F\x1E\x33', 'LLIL_SET_REG.d(w14,LLIL_AND.d(LLIL_CONST.d(0xFC000003),LLIL_REG.d(w14)))'), # bfc w14, #2, #24
	# BFC_BFM_64M_bitfield 1011001101xxxxxxxxxxxxxxxxxxxxxx
	(b'\xF8\x5B\x74\xB3', 'LLIL_SET_REG.q(x24,LLIL_AND.q(LLIL_CONST.q(0xFFFFFFF800000FFF),LLIL_REG.q(x24)))'), # bfc x24, #12, #23
	(b'\xF4\x67\x77\xB3', 'LLIL_SET_REG.q(x20,LLIL_AND.q(LLIL_CONST.q(0xFFFFFFF8000001FF),LLIL_REG.q(x20)))'), # bfc x20, #9, #26
	(b'\xFF\x5F\x6B\xB3', 'LLIL_SET_REG.q(xzr,LLIL_CONST.q(0x0))'), # bfc xzr, #21, #24
	(b'\xE0\x17\x5D\xB3', 'LLIL_SET_REG.q(x0,LLIL_AND.q(LLIL_CONST.q(0xFFFFFE07FFFFFFFF),LLIL_REG.q(x0)))'), # bfc x0, #35, #6
	# BFI_BFM_32M_bitfield 00110011000xxxxx0xxxxxxxxxxxxxxx
	(b'\xC3\x1D\x1C\x33', 'LLIL_SET_REG.d(w3,LLIL_OR.d(LLIL_AND.d(LLIL_CONST.d(0xFFFFF00F),LLIL_REG.d(w3)),LLIL_LSL.d(LLIL_AND.d(LLIL_CONST.d(0xFF),LLIL_REG.d(w14)),LLIL_CONST(4))))'), # bfi w3, w14, #4, #8
	(b'\x71\x23\x0C\x33', 'LLIL_SET_REG.d(w17,LLIL_OR.d(LLIL_AND.d(LLIL_CONST.d(0xE00FFFFF),LLIL_REG.d(w17)),LLIL_LSL.d(LLIL_AND.d(LLIL_CONST.d(0x1FF),LLIL_REG.d(w27)),LLIL_CONST(20))))'), # bfi w17, w27, #20, #9
	(b'\x2F\x3A\x14\x33', 'LLIL_SET_REG.d(w15,LLIL_OR.d(LLIL_AND.d(LLIL_CONST.d(0xF8000FFF),LLIL_REG.d(w15)),LLIL_LSL.d(LLIL_AND.d(LLIL_CONST.d(0x7FFF),LLIL_REG.d(w17)),LLIL_CONST(12))))'), # bfi w15, w17, #12, #15
	(b'\x42\x0C\x0A\x33', 'LLIL_SET_REG.d(w2,LLIL_OR.d(LLIL_AND.d(LLIL_CONST.d(0xFC3FFFFF),LLIL_REG.d(w2)),LLIL_LSL.d(LLIL_AND.d(LLIL_CONST.d(0xF),LLIL_REG.d(w2)),LLIL_CONST(22))))'), # bfi w2, w2, #22, #4
	# BFI_BFM_64M_bitfield 1011001101xxxxxxxxxxxxxxxxxxxxxx
	(b'\xE9\x05\x71\xB3', 'LLIL_SET_REG.q(x9,LLIL_OR.q(LLIL_AND.q(LLIL_CONST.q(0xFFFFFFFFFFFE7FFF),LLIL_REG.q(x9)),LLIL_LSL.q(LLIL_AND.q(LLIL_CONST.q(0x3),LLIL_REG.q(x15)),LLIL_CONST(15))))'), # bfi x9, x15, #15, #2
	(b'\x80\x3C\x74\xB3', 'LLIL_SET_REG.q(x0,LLIL_OR.q(LLIL_AND.q(LLIL_CONST.q(0xFFFFFFFFF0000FFF),LLIL_REG.q(x0)),LLIL_LSL.q(LLIL_AND.q(LLIL_CONST.q(0xFFFF),LLIL_REG.q(x4)),LLIL_CONST(12))))'), # bfi x0, x4, #12, #16
	(b'\x76\x6B\x7B\xB3', 'LLIL_SET_REG.q(x22,LLIL_OR.q(LLIL_AND.q(LLIL_CONST.q(0xFFFFFFFF0000001F),LLIL_REG.q(x22)),LLIL_LSL.q(LLIL_AND.q(LLIL_CONST.q(0x7FFFFFF),LLIL_REG.q(x27)),LLIL_CONST(5))))'), # bfi x22, x27, #5, #27
	(b'\xD1\x03\x7F\xB3', 'LLIL_SET_REG.q(x17,LLIL_OR.q(LLIL_AND.q(LLIL_CONST.q(0xFFFFFFFFFFFFFFFD),LLIL_REG.q(x17)),LLIL_LSL.q(LLIL_AND.q(LLIL_CONST.q(0x1),LLIL_REG.q(x30)),LLIL_CONST(1))))'), # bfi x17, x30, #1, #1
	# BFXIL_BFM_32M_bitfield 00110011000xxxxxxxxxxxxxxxxxxxxx
	(b'\x99\x2B\x06\x33', 'LLIL_SET_REG.d(w25,LLIL_OR.d(LLIL_AND.d(LLIL_REG.d(w25),LLIL_CONST.d(0xFFFFFFE0)),LLIL_LSR.d(LLIL_AND.d(LLIL_REG.d(w28),LLIL_CONST.d(0x7C0)),LLIL_CONST(6))))'), # bfxil w25, w28, #6, #5
	(b'\x83\x4A\x01\x33', 'LLIL_SET_REG.d(w3,LLIL_OR.d(LLIL_AND.d(LLIL_REG.d(w3),LLIL_CONST.d(0xFFFC0000)),LLIL_LSR.d(LLIL_AND.d(LLIL_REG.d(w20),LLIL_CONST.d(0x7FFFE)),LLIL_CONST(1))))'), # bfxil w3, w20, #1, #18
	(b'\x1C\x29\x09\x33', 'LLIL_SET_REG.d(w28,LLIL_OR.d(LLIL_AND.d(LLIL_REG.d(w28),LLIL_CONST.d(0xFFFFFFFC)),LLIL_LSR.d(LLIL_AND.d(LLIL_REG.d(w8),LLIL_CONST.d(0x600)),LLIL_CONST(9))))'), # bfxil w28, w8, #9, #2
	(b'\xF9\x7A\x16\x33', 'LLIL_SET_REG.d(w25,LLIL_OR.d(LLIL_AND.d(LLIL_REG.d(w25),LLIL_CONST.d(0xFFFFFE00)),LLIL_LSR.d(LLIL_AND.d(LLIL_REG.d(w23),LLIL_CONST.d(0x7FC00000)),LLIL_CONST(22))))'), # bfxil w25, w23, #22, #9
	# BFXIL_BFM_64M_bitfield 1011001101xxxxxxxxxxxxxxxxxxxxxx
	(b'\xF1\xC1\x65\xB3', 'LLIL_SET_REG.q(x17,LLIL_OR.q(LLIL_AND.q(LLIL_REG.q(x17),LLIL_CONST.q(0xFFFFFFFFFFFFF000)),LLIL_LSR.q(LLIL_AND.q(LLIL_REG.q(x15),LLIL_CONST.q(0x1FFE000000000)),LLIL_CONST(37))))'), # bfxil x17, x15, #37, #12
	(b'\x25\xF0\x51\xB3', 'LLIL_SET_REG.q(x5,LLIL_OR.q(LLIL_AND.q(LLIL_REG.q(x5),LLIL_CONST.q(0xFFFFF00000000000)),LLIL_LSR.q(LLIL_AND.q(LLIL_REG.q(x1),LLIL_CONST.q(0x1FFFFFFFFFFE0000)),LLIL_CONST(17))))'), # bfxil x5, x1, #17, #44
	(b'\x6E\xBE\x48\xB3', 'LLIL_SET_REG.q(x14,LLIL_OR.q(LLIL_AND.q(LLIL_REG.q(x14),LLIL_CONST.q(0xFFFFFF0000000000)),LLIL_LSR.q(LLIL_AND.q(LLIL_REG.q(x19),LLIL_CONST.q(0xFFFFFFFFFF00)),LLIL_CONST(8))))'), # bfxil x14, x19, #8, #40
	(b'\x0D\xF0\x48\xB3', 'LLIL_SET_REG.q(x13,LLIL_OR.q(LLIL_AND.q(LLIL_REG.q(x13),LLIL_CONST.q(0xFFE0000000000000)),LLIL_LSR.q(LLIL_AND.q(LLIL_REG.q(x0),LLIL_CONST.q(0x1FFFFFFFFFFFFF00)),LLIL_CONST(8))))'), # bfxil x13, x0, #8, #53
	(b'\x62\xFC\x40\xB3', 'LLIL_SET_REG.q(x2,LLIL_LSR.q(LLIL_AND.q(LLIL_REG.q(x3),LLIL_CONST.q(0xFFFFFFFFFFFFFFFF)),LLIL_CONST(0)))'), # bfxil x2, x3, #0, #0x40
	(b'\xe0\xff\x40\xb3', 'LLIL_SET_REG.q(x0,LLIL_LSR.q(LLIL_CONST.q(0x0),LLIL_CONST(0)))'), # bfxil x0, xzr, #0, #64
	# str instructions
	# STR_32_ldst_immpost 10111000000xxxxxxxxx01xxxxxxxxxx
	(b'\xC4\xA5\x15\xB8', 'LLIL_STORE.d(LLIL_REG.q(x14),LLIL_REG.d(w4)); LLIL_SET_REG.q(x14,LLIL_ADD.q(LLIL_REG.q(x14),LLIL_CONST.q(0xFFFFFFFFFFFFFF5A)))'), # str w4, [x14], #-166
	(b'\x30\xD7\x10\xB8', 'LLIL_STORE.d(LLIL_REG.q(x25),LLIL_REG.d(w16)); LLIL_SET_REG.q(x25,LLIL_ADD.q(LLIL_REG.q(x25),LLIL_CONST.q(0xFFFFFFFFFFFFFF0D)))'), # str w16, [x25], #-243
	(b'\xC7\x24\x0A\xB8', 'LLIL_STORE.d(LLIL_REG.q(x6),LLIL_REG.d(w7)); LLIL_SET_REG.q(x6,LLIL_ADD.q(LLIL_REG.q(x6),LLIL_CONST.q(0xA2)))'), # str w7, [x6], #162
	(b'\xA8\xF4\x01\xB8', 'LLIL_STORE.d(LLIL_REG.q(x5),LLIL_REG.d(w8)); LLIL_SET_REG.q(x5,LLIL_ADD.q(LLIL_REG.q(x5),LLIL_CONST.q(0x1F)))'), # str w8, [x5], #31
	# STR_32_ldst_immpre 10111000000xxxxxxxxx11xxxxxxxxxx
	(b'\x54\xCD\x07\xB8', 'LLIL_SET_REG.q(x10,LLIL_ADD.q(LLIL_REG.q(x10),LLIL_CONST.q(0x7C))); LLIL_STORE.d(LLIL_REG.q(x10),LLIL_REG.d(w20))'), # str w20, [x10, #124]!
	(b'\x6A\x0E\x0A\xB8', 'LLIL_SET_REG.q(x19,LLIL_ADD.q(LLIL_REG.q(x19),LLIL_CONST.q(0xA0))); LLIL_STORE.d(LLIL_REG.q(x19),LLIL_REG.d(w10))'), # str w10, [x19, #160]!
	(b'\xC5\x3C\x18\xB8', 'LLIL_SET_REG.q(x6,LLIL_ADD.q(LLIL_REG.q(x6),LLIL_CONST.q(0xFFFFFFFFFFFFFF83))); LLIL_STORE.d(LLIL_REG.q(x6),LLIL_REG.d(w5))'), # str w5, [x6, #-125]!
	(b'\x40\x5D\x1F\xB8', 'LLIL_SET_REG.q(x10,LLIL_ADD.q(LLIL_REG.q(x10),LLIL_CONST.q(0xFFFFFFFFFFFFFFF5))); LLIL_STORE.d(LLIL_REG.q(x10),LLIL_REG.d(w0))'), # str w0, [x10, #-11]!
	# STR_32_ldst_pos 1011100100xxxxxxxxxxxxxxxxxxxxxx
	(b'\x3C\xD5\x3B\xB9', 'LLIL_STORE.d(LLIL_ADD.q(LLIL_REG.q(x9),LLIL_CONST.q(0x3BD4)),LLIL_REG.d(w28))'), # str w28, [x9, #15316]
	(b'\xF4\xAA\x08\xB9', 'LLIL_STORE.d(LLIL_ADD.q(LLIL_REG.q(x23),LLIL_CONST.q(0x8A8)),LLIL_REG.d(w20))'), # str w20, [x23, #2216]
	(b'\x04\x91\x10\xB9', 'LLIL_STORE.d(LLIL_ADD.q(LLIL_REG.q(x8),LLIL_CONST.q(0x1090)),LLIL_REG.d(w4))'), # str w4, [x8, #4240]
	(b'\x73\xE3\x06\xB9', 'LLIL_STORE.d(LLIL_ADD.q(LLIL_REG.q(x27),LLIL_CONST.q(0x6E0)),LLIL_REG.d(w19))'), # str w19, [x27, #1760]
	# STR_32_ldst_regoff 10111000001xxxxxx1xx10xxxxxxxxxx
	(b'\x49\x79\x25\xB8', 'LLIL_STORE.d(LLIL_ADD.q(LLIL_REG.q(x10),LLIL_LSL.q(LLIL_REG.q(x5),LLIL_CONST.b(0x2))),LLIL_REG.d(w9))'), # str w9, [x10, x5, lsl #2]
	(b'\x5C\x7B\x27\xB8', 'LLIL_STORE.d(LLIL_ADD.q(LLIL_REG.q(x26),LLIL_LSL.q(LLIL_REG.q(x7),LLIL_CONST.b(0x2))),LLIL_REG.d(w28))'), # str w28, [x26, x7, lsl #2]
	(b'\xFA\xF8\x27\xB8', 'LLIL_STORE.d(LLIL_ADD.q(LLIL_REG.q(x7),LLIL_LSL.q(LLIL_REG.q(x7),LLIL_CONST.b(0x2))),LLIL_REG.d(w26))'), # str w26, [x7, x7, sxtx #2]
	(b'\xB0\xEB\x38\xB8', 'LLIL_STORE.d(LLIL_ADD.q(LLIL_REG.q(x29),LLIL_REG.q(x24)),LLIL_REG.d(w16))'), # str w16, [x29, x24, sxtx]
	# STR_64_ldst_immpost 11111000000xxxxxxxxx01xxxxxxxxxx
	(b'\x34\x45\x06\xF8', 'LLIL_STORE.q(LLIL_REG.q(x9),LLIL_REG.q(x20)); LLIL_SET_REG.q(x9,LLIL_ADD.q(LLIL_REG.q(x9),LLIL_CONST.q(0x64)))'), # str x20, [x9], #100
	(b'\x2E\xE6\x0B\xF8', 'LLIL_STORE.q(LLIL_REG.q(x17),LLIL_REG.q(x14)); LLIL_SET_REG.q(x17,LLIL_ADD.q(LLIL_REG.q(x17),LLIL_CONST.q(0xBE)))'), # str x14, [x17], #190
	(b'\x1F\xB4\x0B\xF8', 'LLIL_STORE.q(LLIL_REG.q(x0),LLIL_CONST.q(0x0)); LLIL_SET_REG.q(x0,LLIL_ADD.q(LLIL_REG.q(x0),LLIL_CONST.q(0xBB)))'), # str xzr, [x0], #187
	(b'\x90\xD5\x1E\xF8', 'LLIL_STORE.q(LLIL_REG.q(x12),LLIL_REG.q(x16)); LLIL_SET_REG.q(x12,LLIL_ADD.q(LLIL_REG.q(x12),LLIL_CONST.q(0xFFFFFFFFFFFFFFED)))'), # str x16, [x12], #-19
	# STR_64_ldst_immpre 11111000000xxxxxxxxx11xxxxxxxxxx
	(b'\x94\xEE\x19\xF8', 'LLIL_SET_REG.q(x20,LLIL_ADD.q(LLIL_REG.q(x20),LLIL_CONST.q(0xFFFFFFFFFFFFFF9E))); LLIL_STORE.q(LLIL_REG.q(x20),LLIL_REG.q(x20))'), # str x20, [x20, #-98]!
	(b'\x34\xBC\x0F\xF8', 'LLIL_SET_REG.q(x1,LLIL_ADD.q(LLIL_REG.q(x1),LLIL_CONST.q(0xFB))); LLIL_STORE.q(LLIL_REG.q(x1),LLIL_REG.q(x20))'), # str x20, [x1, #251]!
	(b'\x71\xFC\x04\xF8', 'LLIL_SET_REG.q(x3,LLIL_ADD.q(LLIL_REG.q(x3),LLIL_CONST.q(0x4F))); LLIL_STORE.q(LLIL_REG.q(x3),LLIL_REG.q(x17))'), # str x17, [x3, #79]!
	(b'\xC3\xBC\x1E\xF8', 'LLIL_SET_REG.q(x6,LLIL_ADD.q(LLIL_REG.q(x6),LLIL_CONST.q(0xFFFFFFFFFFFFFFEB))); LLIL_STORE.q(LLIL_REG.q(x6),LLIL_REG.q(x3))'), # str x3, [x6, #-21]!
	# STR_64_ldst_pos 1111100100xxxxxxxxxxxxxxxxxxxxxx
	(b'\xED\x1A\x3C\xF9', 'LLIL_STORE.q(LLIL_ADD.q(LLIL_REG.q(x23),LLIL_CONST.q(0x7830)),LLIL_REG.q(x13))'), # str x13, [x23, #30768]
	(b'\xA3\xA0\x21\xF9', 'LLIL_STORE.q(LLIL_ADD.q(LLIL_REG.q(x5),LLIL_CONST.q(0x4340)),LLIL_REG.q(x3))'), # str x3, [x5, #17216]
	(b'\x19\x88\x2F\xF9', 'LLIL_STORE.q(LLIL_ADD.q(LLIL_REG.q(x0),LLIL_CONST.q(0x5F10)),LLIL_REG.q(x25))'), # str x25, [x0, #24336]
	(b'\xBD\x8C\x14\xF9', 'LLIL_STORE.q(LLIL_ADD.q(LLIL_REG.q(x5),LLIL_CONST.q(0x2918)),LLIL_REG.q(x29))'), # str x29, [x5, #10520]
	# STR_64_ldst_regoff 11111000001xxxxxx1xx10xxxxxxxxxx
	(b'\xD3\xE9\x21\xF8', 'LLIL_STORE.q(LLIL_ADD.q(LLIL_REG.q(x14),LLIL_REG.q(x1)),LLIL_REG.q(x19))'), # str x19, [x14, x1, sxtx]
	(b'\xA2\x58\x25\xF8', 'LLIL_STORE.q(LLIL_ADD.q(LLIL_REG.q(x5),LLIL_LSL.q(LLIL_ZX.q(LLIL_REG.d(w5)),LLIL_CONST.b(0x3))),LLIL_REG.q(x2))'), # str x2, [x5, w5, uxtw #3]
	(b'\xF4\xFA\x3A\xF8', 'LLIL_STORE.q(LLIL_ADD.q(LLIL_REG.q(x23),LLIL_LSL.q(LLIL_REG.q(x26),LLIL_CONST.b(0x3))),LLIL_REG.q(x20))'), # str x20, [x23, x26, sxtx #3]
	(b'\xEE\xF9\x34\xF8', 'LLIL_STORE.q(LLIL_ADD.q(LLIL_REG.q(x15),LLIL_LSL.q(LLIL_REG.q(x20),LLIL_CONST.b(0x3))),LLIL_REG.q(x14))'), # str x14, [x15, x20, sxtx #3]
	# IFORM: STR_reg_fpsimd
	# STR_B_ldst_regoff 00111100001xxxxxx1xx10xxxxxxxxxx
	(b'\xFD\xD8\x27\x3C', 'LLIL_STORE.b(LLIL_ADD.q(LLIL_REG.q(x7),LLIL_SX.q(LLIL_REG.d(w7))),LLIL_REG.b(b29))'), # str b29, [x7, w7, sxtw #0]
	(b'\x20\xDA\x30\x3C', 'LLIL_STORE.b(LLIL_ADD.q(LLIL_REG.q(x17),LLIL_SX.q(LLIL_REG.d(w16))),LLIL_REG.b(b0))'), # str b0, [x17, w16, sxtw #0]
	# STR_BL_ldst_regoff 00111100001xxxxx011x10xxxxxxxxxx
	(b'\xCC\x7B\x27\x3C', 'LLIL_STORE.b(LLIL_ADD.q(LLIL_REG.q(x30),LLIL_REG.q(x7)),LLIL_REG.b(b12))'), # str b12, [x30, x7, lsl #0]
	(b'\x1F\x79\x3A\x3C', 'LLIL_STORE.b(LLIL_ADD.q(LLIL_REG.q(x8),LLIL_REG.q(x26)),LLIL_REG.b(b31))'), # str b31, [x8, x26, lsl #0]
	# STR_H_ldst_regoff 01111100001xxxxxx1xx10xxxxxxxxxx
	(b'\xCE\xD9\x36\x7C', 'LLIL_STORE.w(LLIL_ADD.q(LLIL_REG.q(x14),LLIL_LSL.q(LLIL_SX.q(LLIL_REG.d(w22)),LLIL_CONST.b(0x1))),LLIL_REG.w(h14))'), # str h14, [x14, w22, sxtw #1]
	(b'\x39\xCB\x2D\x7C', 'LLIL_STORE.w(LLIL_ADD.q(LLIL_REG.q(x25),LLIL_SX.q(LLIL_REG.d(w13))),LLIL_REG.w(h25))'), # str h25, [x25, w13, sxtw]
	# STR_S_ldst_regoff 10111100001xxxxxx1xx10xxxxxxxxxx
	(b'\xB5\x79\x3F\xBC', 'LLIL_STORE.d(LLIL_ADD.q(LLIL_REG.q(x13),LLIL_LSL.q(LLIL_CONST.q(0x0),LLIL_CONST.b(0x2))),LLIL_REG.d(s21))'), # str s21, [x13, xzr, lsl #2]
	(b'\x8B\x7B\x2C\xBC', 'LLIL_STORE.d(LLIL_ADD.q(LLIL_REG.q(x28),LLIL_LSL.q(LLIL_REG.q(x12),LLIL_CONST.b(0x2))),LLIL_REG.d(s11))'), # str s11, [x28, x12, lsl #2]
	# STR_D_ldst_regoff 11111100001xxxxxx1xx10xxxxxxxxxx
	(b'\x2C\x59\x22\xFC', 'LLIL_STORE.q(LLIL_ADD.q(LLIL_REG.q(x9),LLIL_LSL.q(LLIL_ZX.q(LLIL_REG.d(w2)),LLIL_CONST.b(0x3))),LLIL_REG.q(d12))'), # str d12, [x9, w2, uxtw #3]
	(b'\x25\xD9\x22\xFC', 'LLIL_STORE.q(LLIL_ADD.q(LLIL_REG.q(x9),LLIL_LSL.q(LLIL_SX.q(LLIL_REG.d(w2)),LLIL_CONST.b(0x3))),LLIL_REG.q(d5))'), # str d5, [x9, w2, sxtw #3]
	# STR_Q_ldst_regoff 00111100101xxxxxx1xx10xxxxxxxxxx
	(b'\x0B\xCB\xA1\x3C', 'LLIL_STORE.128(LLIL_ADD.q(LLIL_REG.q(x24),LLIL_SX.q(LLIL_REG.d(w1))),LLIL_REG.128(q11))'), # str q11, [x24, w1, sxtw]
	(b'\x8E\xCB\xBD\x3C', 'LLIL_STORE.128(LLIL_ADD.q(LLIL_REG.q(x28),LLIL_SX.q(LLIL_REG.d(w29))),LLIL_REG.128(q14))'), # str q14, [x28, w29, sxtw]
	# IFORM: STR_imm_fpsimd (class post_indexed)
	# STR_B_ldst_immpost 00111100000xxxxxxxxx01xxxxxxxxxx
	(b'\xB6\x57\x07\x3C', 'LLIL_STORE.b(LLIL_REG.q(x29),LLIL_REG.b(b22)); LLIL_SET_REG.q(x29,LLIL_ADD.q(LLIL_REG.q(x29),LLIL_CONST.q(0x75)))'), # str b22, [x29], #117
	(b'\x0F\xE7\x0C\x3C', 'LLIL_STORE.b(LLIL_REG.q(x24),LLIL_REG.b(b15)); LLIL_SET_REG.q(x24,LLIL_ADD.q(LLIL_REG.q(x24),LLIL_CONST.q(0xCE)))'), # str b15, [x24], #206
	# STR_H_ldst_immpost 01111100000xxxxxxxxx01xxxxxxxxxx
	(b'\x56\xC6\x01\x7C', 'LLIL_STORE.w(LLIL_REG.q(x18),LLIL_REG.w(h22)); LLIL_SET_REG.q(x18,LLIL_ADD.q(LLIL_REG.q(x18),LLIL_CONST.q(0x1C)))'), # str h22, [x18], #28
	(b'\x93\xD7\x07\x7C', 'LLIL_STORE.w(LLIL_REG.q(x28),LLIL_REG.w(h19)); LLIL_SET_REG.q(x28,LLIL_ADD.q(LLIL_REG.q(x28),LLIL_CONST.q(0x7D)))'), # str h19, [x28], #125
	# STR_S_ldst_immpost 10111100000xxxxxxxxx01xxxxxxxxxx
	(b'\x9E\x06\x13\xBC', 'LLIL_STORE.d(LLIL_REG.q(x20),LLIL_REG.d(s30)); LLIL_SET_REG.q(x20,LLIL_ADD.q(LLIL_REG.q(x20),LLIL_CONST.q(0xFFFFFFFFFFFFFF30)))'), # str s30, [x20], #-208
	(b'\xA9\x07\x07\xBC', 'LLIL_STORE.d(LLIL_REG.q(x29),LLIL_REG.d(s9)); LLIL_SET_REG.q(x29,LLIL_ADD.q(LLIL_REG.q(x29),LLIL_CONST.q(0x70)))'), # str s9, [x29], #112
	# STR_D_ldst_immpost 11111100000xxxxxxxxx01xxxxxxxxxx
	(b'\xAD\xE4\x1F\xFC', 'LLIL_STORE.q(LLIL_REG.q(x5),LLIL_REG.q(d13)); LLIL_SET_REG.q(x5,LLIL_ADD.q(LLIL_REG.q(x5),LLIL_CONST.q(0xFFFFFFFFFFFFFFFE)))'), # str d13, [x5], #-2
	(b'\xE3\x64\x15\xFC', 'LLIL_STORE.q(LLIL_REG.q(x7),LLIL_REG.q(d3)); LLIL_SET_REG.q(x7,LLIL_ADD.q(LLIL_REG.q(x7),LLIL_CONST.q(0xFFFFFFFFFFFFFF56)))'), # str d3, [x7], #-170
	# STR_Q_ldst_immpost 00111100100xxxxxxxxx01xxxxxxxxxx
	(b'\xAD\xA5\x9A\x3C', 'LLIL_STORE.128(LLIL_REG.q(x13),LLIL_REG.128(q13)); LLIL_SET_REG.q(x13,LLIL_ADD.q(LLIL_REG.q(x13),LLIL_CONST.q(0xFFFFFFFFFFFFFFAA)))'), # str q13, [x13], #-86
	(b'\x6C\x15\x8B\x3C', 'LLIL_STORE.128(LLIL_REG.q(x11),LLIL_REG.128(q12)); LLIL_SET_REG.q(x11,LLIL_ADD.q(LLIL_REG.q(x11),LLIL_CONST.q(0xB1)))'), # str q12, [x11], #177
	# IFORM: STR_imm_fpsimd (class pre_indexed)
	# STR_B_ldst_immpre 00111100000xxxxxxxxx11xxxxxxxxxx
	(b'\x26\xBF\x00\x3C', 'LLIL_SET_REG.q(x25,LLIL_ADD.q(LLIL_REG.q(x25),LLIL_CONST.q(0xB))); LLIL_STORE.b(LLIL_REG.q(x25),LLIL_REG.b(b6))'), # str b6, [x25, #11]!
	(b'\x8A\xED\x0E\x3C', 'LLIL_SET_REG.q(x12,LLIL_ADD.q(LLIL_REG.q(x12),LLIL_CONST.q(0xEE))); LLIL_STORE.b(LLIL_REG.q(x12),LLIL_REG.b(b10))'), # str b10, [x12, #238]!
	# STR_H_ldst_immpre 01111100000xxxxxxxxx11xxxxxxxxxx
	(b'\xFA\xBC\x03\x7C', 'LLIL_SET_REG.q(x7,LLIL_ADD.q(LLIL_REG.q(x7),LLIL_CONST.q(0x3B))); LLIL_STORE.w(LLIL_REG.q(x7),LLIL_REG.w(h26))'), # str h26, [x7, #59]!
	(b'\xBE\x3E\x1E\x7C', 'LLIL_SET_REG.q(x21,LLIL_ADD.q(LLIL_REG.q(x21),LLIL_CONST.q(0xFFFFFFFFFFFFFFE3))); LLIL_STORE.w(LLIL_REG.q(x21),LLIL_REG.w(h30))'), # str h30, [x21, #-29]!
	# STR_S_ldst_immpre 10111100000xxxxxxxxx11xxxxxxxxxx
	(b'\xD6\x4E\x13\xBC', 'LLIL_SET_REG.q(x22,LLIL_ADD.q(LLIL_REG.q(x22),LLIL_CONST.q(0xFFFFFFFFFFFFFF34))); LLIL_STORE.d(LLIL_REG.q(x22),LLIL_REG.d(s22))'), # str s22, [x22, #-204]!
	(b'\xDC\xFF\x09\xBC', 'LLIL_SET_REG.q(x30,LLIL_ADD.q(LLIL_REG.q(x30),LLIL_CONST.q(0x9F))); LLIL_STORE.d(LLIL_REG.q(x30),LLIL_REG.d(s28))'), # str s28, [x30, #159]!
	# STR_D_ldst_immpre 11111100000xxxxxxxxx11xxxxxxxxxx
	(b'\x04\xEF\x1B\xFC', 'LLIL_SET_REG.q(x24,LLIL_ADD.q(LLIL_REG.q(x24),LLIL_CONST.q(0xFFFFFFFFFFFFFFBE))); LLIL_STORE.q(LLIL_REG.q(x24),LLIL_REG.q(d4))'), # str d4, [x24, #-66]!
	(b'\x71\x6F\x1A\xFC', 'LLIL_SET_REG.q(x27,LLIL_ADD.q(LLIL_REG.q(x27),LLIL_CONST.q(0xFFFFFFFFFFFFFFA6))); LLIL_STORE.q(LLIL_REG.q(x27),LLIL_REG.q(d17))'), # str d17, [x27, #-90]!
	# STR_Q_ldst_immpre 00111100100xxxxxxxxx11xxxxxxxxxx
	(b'\x8B\x8D\x93\x3C', 'LLIL_SET_REG.q(x12,LLIL_ADD.q(LLIL_REG.q(x12),LLIL_CONST.q(0xFFFFFFFFFFFFFF38))); LLIL_STORE.128(LLIL_REG.q(x12),LLIL_REG.128(q11))'), # str q11, [x12, #-200]!
	(b'\x89\xBC\x80\x3C', 'LLIL_SET_REG.q(x4,LLIL_ADD.q(LLIL_REG.q(x4),LLIL_CONST.q(0xB))); LLIL_STORE.128(LLIL_REG.q(x4),LLIL_REG.128(q9))'), # str q9, [x4, #11]!
	# IFORM: STR_imm_fpsimd (class unsigned_scaled_offset)
	# STR_B_ldst_pos 0011110100xxxxxxxxxxxxxxxxxxxxxx
	(b'\x0B\xB2\x30\x3D', 'LLIL_STORE.b(LLIL_ADD.q(LLIL_REG.q(x16),LLIL_CONST.q(0xC2C)),LLIL_REG.b(b11))'), # str b11, [x16, #3116]
	(b'\x5B\xEE\x27\x3D', 'LLIL_STORE.b(LLIL_ADD.q(LLIL_REG.q(x18),LLIL_CONST.q(0x9FB)),LLIL_REG.b(b27))'), # str b27, [x18, #2555]
	# STR_H_ldst_pos 0111110100xxxxxxxxxxxxxxxxxxxxxx
	(b'\x28\x61\x39\x7D', 'LLIL_STORE.w(LLIL_ADD.q(LLIL_REG.q(x9),LLIL_CONST.q(0x1CB0)),LLIL_REG.w(h8))'), # str h8, [x9, #7344]
	(b'\x85\x98\x0C\x7D', 'LLIL_STORE.w(LLIL_ADD.q(LLIL_REG.q(x4),LLIL_CONST.q(0x64C)),LLIL_REG.w(h5))'), # str h5, [x4, #1612]
	# STR_S_ldst_pos 1011110100xxxxxxxxxxxxxxxxxxxxxx
	(b'\x92\xAE\x15\xBD', 'LLIL_STORE.d(LLIL_ADD.q(LLIL_REG.q(x20),LLIL_CONST.q(0x15AC)),LLIL_REG.d(s18))'), # str s18, [x20, #5548]
	(b'\xBF\xD7\x08\xBD', 'LLIL_STORE.d(LLIL_ADD.q(LLIL_REG.q(x29),LLIL_CONST.q(0x8D4)),LLIL_REG.d(s31))'), # str s31, [x29, #2260]
	# STR_D_ldst_pos 1111110100xxxxxxxxxxxxxxxxxxxxxx
	(b'\xF0\xC8\x34\xFD', 'LLIL_STORE.q(LLIL_ADD.q(LLIL_REG.q(x7),LLIL_CONST.q(0x6990)),LLIL_REG.q(d16))'), # str d16, [x7, #27024]
	(b'\xBF\x6F\x17\xFD', 'LLIL_STORE.q(LLIL_ADD.q(LLIL_REG.q(x29),LLIL_CONST.q(0x2ED8)),LLIL_REG.q(d31))'), # str d31, [x29, #11992]
	# STR_Q_ldst_pos 0011110110xxxxxxxxxxxxxxxxxxxxxx
	(b'\x70\x26\x93\x3D', 'LLIL_STORE.128(LLIL_ADD.q(LLIL_REG.q(x19),LLIL_CONST.q(0x4C90)),LLIL_REG.128(q16))'), # str q16, [x19, #19600]
	(b'\xE8\xB0\x88\x3D', 'LLIL_STORE.128(LLIL_ADD.q(LLIL_REG.q(x7),LLIL_CONST.q(0x22C0)),LLIL_REG.128(q8))'), # str q8, [x7, #8896]
	# IFORM: str_p_bi
	# str_p_bi_ 1110010110xxxxxx000xxxxxxxx0xxxx
	#(b'\xA6\x12\xB0\xE5', 'LLIL_UNDEF()'), # str p6, [x21, #-124, mul vl]
	#(b'\x0F\x12\x84\xE5', 'LLIL_UNDEF()'), # str p15, [x16, #36, mul vl]
	# IFORM: str_z_bi
	# str_z_bi_ 1110010110xxxxxx01xxxxxxxxxxxxxx
	#(b'\x11\x55\x89\xE5', 'LLIL_UNDEF()'), # str z17, [x8, #77, mul vl]
	#(b'\x4E\x43\x9B\xE5', 'LLIL_UNDEF()'), # str z14, [x26, #216, mul vl]
	# pointer auth instructions
	# AUTDA_64P_dp_1src 1101101011000001000110xxxxxxxxxx
	(b'\x04\x18\xC1\xDA', 'LLIL_INTRINSIC([x4],__autda,LLIL_CALL_PARAM([LLIL_REG.q(x0)]))'), # autda x4, x0
	(b'\xF4\x18\xC1\xDA', 'LLIL_INTRINSIC([x20],__autda,LLIL_CALL_PARAM([LLIL_REG.q(x7)]))'), # autda x20, x7
	# AUTDB_64P_dp_1src 110110101100000100xxxxxxxxxxxxxx
	(b'\x94\x1C\xC1\xDA', 'LLIL_INTRINSIC([x20],__autdb,LLIL_CALL_PARAM([LLIL_REG.q(x4)]))'), # autdb x20, x4
	(b'\xCB\x1E\xC1\xDA', 'LLIL_INTRINSIC([x11],__autdb,LLIL_CALL_PARAM([LLIL_REG.q(x22)]))'), # autdb x11, x22
	# AUTDZA_64Z_dp_1src 110110101100000100111xxxxxxxxxxx
	(b'\xF3\x3B\xC1\xDA', 'LLIL_INTRINSIC([x19],__autdza,LLIL_CALL_PARAM([]))'), # autdza x19
	(b'\xF4\x3B\xC1\xDA', 'LLIL_INTRINSIC([x20],__autdza,LLIL_CALL_PARAM([]))'), # autdza x20
	# AUTDZB_64Z_dp_1src 11011010110000010xxxxxxxxxxxxxxx
	(b'\xFE\x3F\xC1\xDA', 'LLIL_INTRINSIC([x30],__autdzb,LLIL_CALL_PARAM([]))'), # autdzb x30
	(b'\xEE\x3F\xC1\xDA', 'LLIL_INTRINSIC([x14],__autdzb,LLIL_CALL_PARAM([]))'), # autdzb x14
	# AUTIA_64P_dp_1src 1101101011000001000100xxxxxxxxxx
	(b'\x83\x11\xC1\xDA', 'LLIL_INTRINSIC([x3],__autia,LLIL_CALL_PARAM([LLIL_REG.q(x12)]))'), # autia x3, x12
	(b'\xD5\x13\xC1\xDA', 'LLIL_INTRINSIC([x21],__autia,LLIL_CALL_PARAM([LLIL_REG.q(x30)]))'), # autia x21, x30
	# AUTIB1716_HI_hints 1101010100000011001000xxxxxxxxxx
	(b'\xDF\x21\x03\xD5', 'LLIL_INTRINSIC([x17],__autib1716,LLIL_CALL_PARAM([LLIL_REG.q(x16)]))'), # autib1716
	# AUTIBSP_HI_hints 110101010000001100100xxxxxxxxxxx
	(b'\xFF\x23\x03\xD5', 'LLIL_INTRINSIC([x30],__autibsp,LLIL_CALL_PARAM([LLIL_REG.q(sp)]))'), # autibsp
	# AUTIBZ_HI_hints 11010101000000110010001111xxxxxx
	(b'\xDF\x23\x03\xD5', 'LLIL_INTRINSIC([x30],__autibz,LLIL_CALL_PARAM([]))'), # autibz
	# AUTIB_64P_dp_1src 1101101011000001000101xxxxxxxxxx
	(b'\x7C\x16\xC1\xDA', 'LLIL_INTRINSIC([x28],__autib,LLIL_CALL_PARAM([LLIL_REG.q(x19)]))'), # autib x28, x19
	(b'\xCB\x16\xC1\xDA', 'LLIL_INTRINSIC([x11],__autib,LLIL_CALL_PARAM([LLIL_REG.q(x22)]))'), # autib x11, x22
	# AUTIZA_64Z_dp_1src 110110101100000100110xxxxxxxxxxx
	(b'\xEF\x33\xC1\xDA', 'LLIL_INTRINSIC([x15],__autiza,LLIL_CALL_PARAM([]))'), # autiza x15
	(b'\xF5\x33\xC1\xDA', 'LLIL_INTRINSIC([x21],__autiza,LLIL_CALL_PARAM([]))'), # autiza x21
	# AUTIZB_64Z_dp_1src 11011010110000010011xxxxxxxxxxxx
	(b'\xE4\x37\xC1\xDA', 'LLIL_INTRINSIC([x4],__autizb,LLIL_CALL_PARAM([]))'), # autizb x4
	(b'\xF4\x37\xC1\xDA', 'LLIL_INTRINSIC([x20],__autizb,LLIL_CALL_PARAM([]))'), # autizb x20
	# BLRAA_64P_branch_reg 1101011100111111000010xxxxxxxxxx
	(b'\x14\x0B\x3F\xD7', 'LLIL_CALL(LLIL_REG.q(x24))'), # blraa x24, x20
	(b'\xFD\x0A\x3F\xD7', 'LLIL_CALL(LLIL_REG.q(x23))'), # blraa x23, x29
	# BLRAAZ_64_branch_reg 1101011000111111000010xxxxx11111
	(b'\xDF\x09\x3F\xD6', 'LLIL_CALL(LLIL_REG.q(x14))'), # blraaz x14
	(b'\xDF\x08\x3F\xD6', 'LLIL_CALL(LLIL_REG.q(x6))'), # blraaz x6
	# BLRAB_64P_branch_reg 1101011100111111000011xxxxxxxxxx
	(b'\xBA\x0C\x3F\xD7', 'LLIL_CALL(LLIL_REG.q(x5))'), # blrab x5, x26
	(b'\xC2\x0E\x3F\xD7', 'LLIL_CALL(LLIL_REG.q(x22))'), # blrab x22, x2
	# BLRABZ_64_branch_reg 1101011000111111000011xxxxx11111
	(b'\x3F\x0E\x3F\xD6', 'LLIL_CALL(LLIL_REG.q(x17))'), # blrabz x17
	(b'\x3F\x0F\x3F\xD6', 'LLIL_CALL(LLIL_REG.q(x25))'), # blrabz x25
	# BRAAZ_64_branch_reg 1101011000011111000010xxxxx11111
	(b'\x5F\x08\x1F\xD6', 'LLIL_JUMP(LLIL_REG.q(x2))'), # braaz x2
	(b'\x5F\x0A\x1F\xD6', 'LLIL_JUMP(LLIL_REG.q(x18))'), # braaz x18
	# BRAA_64P_branch_reg 1101011100011111000010xxxxxxxxxx
	(b'\x81\x08\x1F\xD7', 'LLIL_JUMP(LLIL_REG.q(x4))'), # braa x4, x1
	(b'\x4C\x09\x1F\xD7', 'LLIL_JUMP(LLIL_REG.q(x10))'), # braa x10, x12
	# BRABZ_64_branch_reg 1101011000011111000011xxxxx11111
	(b'\x3F\x0C\x1F\xD6', 'LLIL_JUMP(LLIL_REG.q(x1))'), # brabz x1
	(b'\xBF\x0E\x1F\xD6', 'LLIL_JUMP(LLIL_REG.q(x21))'), # brabz x21
	# BRAB_64P_branch_reg 1101011100011111000011xxxxxxxxxx
	(b'\x39\x0F\x1F\xD7', 'LLIL_JUMP(LLIL_REG.q(x25))'), # brab x25, x25
	(b'\xA3\x0E\x1F\xD7', 'LLIL_JUMP(LLIL_REG.q(x21))'), # brab x21, x3
	# LDRAA_64W_ldst_pac 111110000x1xxxxxxxxxxxxxxxxxxxxx
	(b'\xAE\x1D\x25\xF8', 'LLIL_SET_REG.q(x13,LLIL_ADD.q(LLIL_REG.q(x13),LLIL_CONST.q(0x288))); LLIL_SET_REG.q(x14,LLIL_LOAD.q(LLIL_REG.q(x13)))'), # ldraa x14, [x13, #648]!
	(b'\x63\x6E\x62\xF8', 'LLIL_SET_REG.q(x19,LLIL_ADD.q(LLIL_REG.q(x19),LLIL_CONST.q(0xFFFFFFFFFFFFF130))); LLIL_SET_REG.q(x3,LLIL_LOAD.q(LLIL_REG.q(x19)))'), # ldraa x3, [x19, #-3792]!
	# LDRAA_64_ldst_pac 111110000x1xxxxxxxxxxxxxxxxxxxxx
	(b'\x90\x15\x62\xF8', 'LLIL_SET_REG.q(x16,LLIL_LOAD.q(LLIL_ADD.q(LLIL_REG.q(x12),LLIL_CONST.q(0xFFFFFFFFFFFFF108))))'), # ldraa x16, [x12, #-3832]
	(b'\x52\x26\x73\xF8', 'LLIL_SET_REG.q(x18,LLIL_LOAD.q(LLIL_ADD.q(LLIL_REG.q(x18),LLIL_CONST.q(0xFFFFFFFFFFFFF990))))'), # ldraa x18, [x18, #-1648]
	# LDRAB_64W_ldst_pac 111110001x1xxxxxxxxx11xxxxxxxxxx
	(b'\x68\xDE\xB8\xF8', 'LLIL_SET_REG.q(x19,LLIL_ADD.q(LLIL_REG.q(x19),LLIL_CONST.q(0xC68))); LLIL_SET_REG.q(x8,LLIL_LOAD.q(LLIL_REG.q(x19)))'), # ldrab x8, [x19, #3176]!
	(b'\x8D\x0D\xFF\xF8', 'LLIL_SET_REG.q(x12,LLIL_ADD.q(LLIL_REG.q(x12),LLIL_CONST.q(0xFFFFFFFFFFFFFF80))); LLIL_SET_REG.q(x13,LLIL_LOAD.q(LLIL_REG.q(x12)))'), # ldrab x13, [x12, #-128]!
	# LDRAB_64_ldst_pac 111110001x1xxxxxxxxxxxxxxxxxxxxx
	(b'\x94\xF5\xA1\xF8', 'LLIL_SET_REG.q(x20,LLIL_LOAD.q(LLIL_ADD.q(LLIL_REG.q(x12),LLIL_CONST.q(0xF8))))'), # ldrab x20, [x12, #248]
	(b'\x2B\x35\xAA\xF8', 'LLIL_SET_REG.q(x11,LLIL_LOAD.q(LLIL_ADD.q(LLIL_REG.q(x9),LLIL_CONST.q(0x518))))'), # ldrab x11, [x9, #1304]
	# PACDA_64P_dp_1src 1101101011000001000010xxxxxxxxxx
	(b'\xAC\x0B\xC1\xDA', 'LLIL_INTRINSIC([x12],__pacda,LLIL_CALL_PARAM([LLIL_REG.q(x29)]))'), # pacda x12, x29
	(b'\xD2\x09\xC1\xDA', 'LLIL_INTRINSIC([x18],__pacda,LLIL_CALL_PARAM([LLIL_REG.q(x14)]))'), # pacda x18, x14
	# PACDB_64P_dp_1src 1101101011000001000011xxxxxxxxxx
	(b'\xF9\x0E\xC1\xDA', 'LLIL_INTRINSIC([x25],__pacdb,LLIL_CALL_PARAM([LLIL_REG.q(x23)]))'), # pacdb x25, x23
	(b'\xBA\x0C\xC1\xDA', 'LLIL_INTRINSIC([x26],__pacdb,LLIL_CALL_PARAM([LLIL_REG.q(x5)]))'), # pacdb x26, x5
	# PACDZA_64Z_dp_1src 110110101100000100101xxxxxxxxxxx
	(b'\xE7\x2B\xC1\xDA', 'LLIL_INTRINSIC([x7],__pacdza,LLIL_CALL_PARAM([]))'), # pacdza x7
	(b'\xF7\x2B\xC1\xDA', 'LLIL_INTRINSIC([x23],__pacdza,LLIL_CALL_PARAM([]))'), # pacdza x23
	# PACDZB_64Z_dp_1src 1101101011000001001xxxxxxxxxxxxx
	(b'\xE6\x2F\xC1\xDA', 'LLIL_INTRINSIC([x6],__pacdzb,LLIL_CALL_PARAM([]))'), # pacdzb x6
	(b'\xE0\x2F\xC1\xDA', 'LLIL_INTRINSIC([x0],__pacdzb,LLIL_CALL_PARAM([]))'), # pacdzb x0
	# PACGA_64P_dp_2src 10011010110xxxxx001100xxxxxxxxxx
	(b'\x22\x30\xCD\x9A', 'LLIL_INTRINSIC([x2],__pacga,LLIL_CALL_PARAM([LLIL_REG.q(x1),LLIL_REG.q(x13)]))'), # pacga x2, x1, x13
	(b'\x99\x32\xD3\x9A', 'LLIL_INTRINSIC([x25],__pacga,LLIL_CALL_PARAM([LLIL_REG.q(x20),LLIL_REG.q(x19)]))'), # pacga x25, x20, x19
	# PACIA1716_HI_hints 1101010100000011001000010xxxxxxx
	(b'\x1F\x21\x03\xD5', 'LLIL_INTRINSIC([x17],__pacia1716,LLIL_CALL_PARAM([LLIL_REG.q(x16)]))'), # pacia1716
	# PACIAZ_HI_hints 11010101000000110010001100xxxxxx
	(b'\x1F\x23\x03\xD5', 'LLIL_INTRINSIC([x30],__paciaz,LLIL_CALL_PARAM([]))'), # paciaz
	# PACIA_64P_dp_1src 1101101011000001000000xxxxxxxxxx
	(b'\x4A\x02\xC1\xDA', 'LLIL_INTRINSIC([x10],__pacia,LLIL_CALL_PARAM([LLIL_REG.q(x18)]))'), # pacia x10, x18
	(b'\xAA\x00\xC1\xDA', 'LLIL_INTRINSIC([x10],__pacia,LLIL_CALL_PARAM([LLIL_REG.q(x5)]))'), # pacia x10, x5
	# PACIB1716_HI_hints 110101010000001100100001xxxxxxxx
	(b'\x5F\x21\x03\xD5', 'LLIL_INTRINSIC([x17],__pacib1716,LLIL_CALL_PARAM([LLIL_REG.q(x16)]))'), # pacib1716
	# PACIASP_HI_hints 1101010100000011001000110xxxxxxx
	# writes x30 (after PAC computation), reads sp for modifier
	(b'\x3F\x23\x03\xD5', 'LLIL_INTRINSIC([x30],__paciasp,LLIL_CALL_PARAM([LLIL_REG.q(sp)]))'), # paciasp
	# PACIBSP_HI_hints 110101010000001100100011xxxxxxxx
	(b'\x7F\x23\x03\xD5', 'LLIL_INTRINSIC([x30],__pacibsp,LLIL_CALL_PARAM([LLIL_REG.q(sp)]))'), # pacibsp
	# PACIBZ_HI_hints 11010101000000110010001101xxxxxx
	(b'\x5F\x23\x03\xD5', 'LLIL_INTRINSIC([x30],__pacibz,LLIL_CALL_PARAM([]))'), # pacibz
	# PACIB_64P_dp_1src 1101101011000001000001xxxxxxxxxx
	(b'\x84\x06\xC1\xDA', 'LLIL_INTRINSIC([x4],__pacib,LLIL_CALL_PARAM([LLIL_REG.q(x20)]))'), # pacib x4, x20
	(b'\x61\x06\xC1\xDA', 'LLIL_INTRINSIC([x1],__pacib,LLIL_CALL_PARAM([LLIL_REG.q(x19)]))'), # pacib x1, x19
	# PACIZA_64Z_dp_1src 110110101100000100100xxxxxxxxxxx
	(b'\xE3\x23\xC1\xDA', 'LLIL_INTRINSIC([x3],__paciza,LLIL_CALL_PARAM([]))'), # paciza x3
	(b'\xFE\x23\xC1\xDA', 'LLIL_INTRINSIC([x30],__paciza,LLIL_CALL_PARAM([]))'), # paciza x30
	# PACIZB_64Z_dp_1src 11011010110000010010xxxxxxxxxxxx
	(b'\xE3\x27\xC1\xDA', 'LLIL_INTRINSIC([x3],__pacizb,LLIL_CALL_PARAM([]))'), # pacizb x3
	(b'\xE7\x27\xC1\xDA', 'LLIL_INTRINSIC([x7],__pacizb,LLIL_CALL_PARAM([]))'), # pacizb x7
	# RETAA_64E_branch_reg 11010110010111110000101111111111
	# (just a return, so function is optimized to nothing)
	(b'\xFF\x0B\x5F\xD6', ''), # retaa
	# RETAB_64E_branch_reg 11010110010111110000111111111111
	(b'\xFF\x0F\x5F\xD6', ''), # retab
	# XPACD_64Z_dp_1src 110110101100000101000111111xxxxx
	(b'\xF8\x47\xC1\xDA', 'LLIL_INTRINSIC([x24],__xpacd,LLIL_CALL_PARAM([]))'), # xpacd x24
	(b'\xED\x47\xC1\xDA', 'LLIL_INTRINSIC([x13],__xpacd,LLIL_CALL_PARAM([]))'), # xpacd x13
	# XPACI_64Z_dp_1src 110110101100000101000xxxxxxxxxxx
	(b'\xE2\x43\xC1\xDA', 'LLIL_INTRINSIC([x2],__xpaci,LLIL_CALL_PARAM([]))'), # xpaci x2
	(b'\xE7\x43\xC1\xDA', 'LLIL_INTRINSIC([x7],__xpaci,LLIL_CALL_PARAM([]))'), # xpaci x7
	# XPACLRI_HI_hints 11010101000000110010000xxxxxxxxx
	(b'\xFF\x20\x03\xD5', 'LLIL_INTRINSIC([x30],__xpaclri,LLIL_CALL_PARAM([]))'), # xpaclri
	# signed bitfield insert zeros, lsb is position in DESTINATION register (position 0 in source)
	# strategy: LSL extracted field to the most significant end, then ASR it back
	(b'\x20\x00\x40\x93', 'LLIL_SET_REG.q(x0,LLIL_ASR.q(LLIL_LSL.q(LLIL_AND.q(LLIL_REG.q(x1),LLIL_CONST.q(0x1)),LLIL_CONST.b(0x3F)),LLIL_CONST.b(0x3F)))'), # sbfiz x0, x1, #0, #1
	(b'\x20\x00\x7f\x93', 'LLIL_SET_REG.q(x0,LLIL_ASR.q(LLIL_LSL.q(LLIL_AND.q(LLIL_REG.q(x1),LLIL_CONST.q(0x1)),LLIL_CONST.b(0x3F)),LLIL_CONST.b(0x3E)))'), # sbfiz x0, x1, #1, #1
	(b'\x20\xfc\x40\x93', 'LLIL_SET_REG.q(x0,LLIL_ASR.q(LLIL_REG.q(x1),LLIL_CONST.q(0x0)))'), # sbfiz x0, x1, #0, #64
	# signed bitfield extract, lsb is position in SOURCE register (position 0 in destination)
	(b'\x20\x00\x40\x93', 'LLIL_SET_REG.q(x0,LLIL_ASR.q(LLIL_LSL.q(LLIL_AND.q(LLIL_REG.q(x1),LLIL_CONST.q(0x1)),LLIL_CONST.b(0x3F)),LLIL_CONST.b(0x3F)))'), # sbfx x0, x1, #0, #1
	(b'\x20\x04\x41\x93', 'LLIL_SET_REG.q(x0,LLIL_ASR.q(LLIL_LSL.q(LLIL_AND.q(LLIL_REG.q(x1),LLIL_CONST.q(0x2)),LLIL_CONST.b(0x3E)),LLIL_CONST.b(0x3F)))'), # sbfx x0, x1, #1, #1
	(b'\x20\xfc\x40\x93', 'LLIL_SET_REG.q(x0,LLIL_ASR.q(LLIL_REG.q(x1),LLIL_CONST.q(0x0)))'), # sbfx x0, x1, #0, #64
	# unsigned bitfield insert zeros, lsb is position in DESTINATION register (position 0 in source)
	# should be same as sbfiz, but logical (LSR) instead of arithmetic (ASR)
	(b'\x20\x00\x40\xd3', 'LLIL_SET_REG.q(x0,LLIL_ZX.q(LLIL_AND.q(LLIL_LSR.q(LLIL_REG.q(x1),LLIL_CONST.b(0x0)),LLIL_CONST.q(0x1))))'), # ubfiz x0, x1, #0, #1
	(b'\x20\x00\x7f\xd3', 'LLIL_SET_REG.q(x0,LLIL_ZX.q(LLIL_LSL.q(LLIL_AND.q(LLIL_REG.q(x1),LLIL_CONST.q(0x1)),LLIL_CONST.b(0x1))))'), # ubfiz x0, x1, #1, #1
	(b'\x20\x04\x40\xd3', 'LLIL_SET_REG.q(x0,LLIL_ZX.q(LLIL_AND.q(LLIL_LSR.q(LLIL_REG.q(x1),LLIL_CONST.b(0x0)),LLIL_CONST.q(0x3))))'), # ubfiz x0, x1, #0, #2
	(b'\x20\x08\x40\xd3', 'LLIL_SET_REG.q(x0,LLIL_ZX.q(LLIL_AND.q(LLIL_LSR.q(LLIL_REG.q(x1),LLIL_CONST.b(0x0)),LLIL_CONST.q(0x7))))'), # ubfiz x0, x1, #0, #3
	(b'\x20\xf8\x40\xd3', 'LLIL_SET_REG.q(x0,LLIL_ZX.q(LLIL_AND.q(LLIL_LSR.q(LLIL_REG.q(x1),LLIL_CONST.b(0x0)),LLIL_CONST.q(0x7FFFFFFFFFFFFFFF))))'), # ubfiz x0, x1, #0, #63
	# ADDS_32S_addsub_ext
	# note: since the shift amount is 0, no LLIL_LSL need be generated
	(b'\x55\x01\x2B\x2B', 'LLIL_SET_REG.d(w21,LLIL_ADD.d(LLIL_REG.d(w10),LLIL_ZX.d(LLIL_LOW_PART.b(LLIL_REG.d(w11)))))'), # adds w21, w10, w11, uxtb
	(b'\xC5\xF2\x24\x2B', 'LLIL_SET_REG.d(w5,LLIL_ADD.d(LLIL_REG.d(w22),LLIL_LSL.d(LLIL_SX.d(LLIL_REG.d(w4)),LLIL_CONST.b(0x4))))'), # adds w5, w22, w4, sxtx #4
	(b'\x11\x29\x35\x2B', 'LLIL_SET_REG.d(w17,LLIL_ADD.d(LLIL_REG.d(w8),LLIL_LSL.d(LLIL_ZX.d(LLIL_LOW_PART.w(LLIL_REG.d(w21))),LLIL_CONST.b(0x2))))'), # adds w17, w8, w21, uxth #2
	(b'\x7E\x31\x3B\x2B', 'LLIL_SET_REG.d(w30,LLIL_ADD.d(LLIL_REG.d(w11),LLIL_LSL.d(LLIL_ZX.d(LLIL_LOW_PART.w(LLIL_REG.d(w27))),LLIL_CONST.b(0x4))))'), # adds w30, w11, w27, uxth #4
	# ADDS_64S_addsub_ext
	(b'\x13\x06\x22\xAB', 'LLIL_SET_REG.q(x19,LLIL_ADD.q(LLIL_REG.q(x16),LLIL_LSL.q(LLIL_ZX.q(LLIL_LOW_PART.b(LLIL_REG.d(w2))),LLIL_CONST.b(0x1))))'), # adds x19, x16, w2, uxtb #1
	(b'\xEF\x06\x21\xAB', 'LLIL_SET_REG.q(x15,LLIL_ADD.q(LLIL_REG.q(x23),LLIL_LSL.q(LLIL_ZX.q(LLIL_LOW_PART.b(LLIL_REG.d(w1))),LLIL_CONST.b(0x1))))'), # adds x15, x23, w1, uxtb #1
	(b'\xFA\xA5\x32\xAB', 'LLIL_SET_REG.q(x26,LLIL_ADD.q(LLIL_REG.q(x15),LLIL_LSL.q(LLIL_SX.q(LLIL_LOW_PART.w(LLIL_REG.d(w18))),LLIL_CONST.b(0x1))))'), # adds x26, x15, w18, sxth #1
	(b'\x00\x04\x20\xab', 'LLIL_SET_REG.q(x0,LLIL_ADD.q(LLIL_REG.q(x0),LLIL_LSL.q(LLIL_ZX.q(LLIL_LOW_PART.b(LLIL_REG.d(w0))),LLIL_CONST.b(0x1))))'), # adds x0, x0, w0, uxtb #0x1
	# note: if size(reg) == size(extend) then no extend (like LLIL_ZX) is needed
	(b'\x25\x6D\x2A\xAB', 'LLIL_SET_REG.q(x5,LLIL_ADD.q(LLIL_REG.q(x9),LLIL_LSL.q(LLIL_REG.q(x10),LLIL_CONST.b(0x3))))'), # adds x5, x9, x10, uxtx #3
	# ADD_32_addsub_ext
	(b'\xB0\x2F\x28\x0B', 'LLIL_SET_REG.d(w16,LLIL_ADD.d(LLIL_REG.d(w29),LLIL_LSL.d(LLIL_ZX.d(LLIL_LOW_PART.w(LLIL_REG.d(w8))),LLIL_CONST.b(0x3))))'), # add w16, w29, w8, uxth #3
	(b'\x4D\x73\x2B\x0B', 'LLIL_SET_REG.d(w13,LLIL_ADD.d(LLIL_REG.d(w26),LLIL_LSL.d(LLIL_ZX.d(LLIL_REG.d(w11)),LLIL_CONST.b(0x4))))'), # add w13, w26, w11, uxtx #4
	(b'\x07\xEE\x2E\x0B', 'LLIL_SET_REG.d(w7,LLIL_ADD.d(LLIL_REG.d(w16),LLIL_LSL.d(LLIL_SX.d(LLIL_REG.d(w14)),LLIL_CONST.b(0x3))))'), # add w7, w16, w14, sxtx #3
	(b'\x28\x63\x31\x0B', 'LLIL_SET_REG.d(w8,LLIL_ADD.d(LLIL_REG.d(w25),LLIL_ZX.d(LLIL_REG.d(w17))))'), # add w8, w25, w17, uxtx
	# ADD_64_addsub_ext
	(b'\xD2\xE8\x2B\x8B', 'LLIL_SET_REG.q(x18,LLIL_ADD.q(LLIL_REG.q(x6),LLIL_LSL.q(LLIL_REG.q(x11),LLIL_CONST.b(0x2))))'), # add x18, x6, x11, sxtx #2
	(b'\x5D\xC4\x2B\x8B', 'LLIL_SET_REG.q(x29,LLIL_ADD.q(LLIL_REG.q(x2),LLIL_LSL.q(LLIL_SX.q(LLIL_REG.d(w11)),LLIL_CONST.b(0x1))))'), # add x29, x2, w11, sxtw #1
	(b'\x82\x49\x31\x8B', 'LLIL_SET_REG.q(x2,LLIL_ADD.q(LLIL_REG.q(x12),LLIL_LSL.q(LLIL_ZX.q(LLIL_REG.d(w17)),LLIL_CONST.b(0x2))))'), # add x2, x12, w17, uxtw #2
	(b'\xFF\xA5\x2C\x8B', 'LLIL_SET_REG.q(sp,LLIL_ADD.q(LLIL_REG.q(x15),LLIL_LSL.q(LLIL_SX.q(LLIL_LOW_PART.w(LLIL_REG.d(w12))),LLIL_CONST.b(0x1))))'), # add sp, x15, w12, sxth #1
	# CMN_ADDS_32S_addsub_ext
	# Compare Negative (extended register) adds a register value and a sign or zero-extended register value, followed by an optional left shift amount.
	(b'\x7F\x8F\x2E\x2B', 'LLIL_ADD.d(LLIL_REG.d(w27),LLIL_LSL.d(LLIL_SX.d(LLIL_LOW_PART.b(LLIL_REG.d(w14))),LLIL_CONST.b(0x3)))'), # cmn w27, w14, sxtb #3
	(b'\x3F\x8E\x3E\x2B', 'LLIL_ADD.d(LLIL_REG.d(w17),LLIL_LSL.d(LLIL_SX.d(LLIL_LOW_PART.b(LLIL_REG.d(w30))),LLIL_CONST.b(0x3)))'), # cmn w17, w30, sxtb #3
	(b'\x3F\x83\x3D\x2B', 'LLIL_ADD.d(LLIL_REG.d(w25),LLIL_SX.d(LLIL_LOW_PART.b(LLIL_REG.d(w29))))'), # cmn w25, w29, sxtb
	(b'\x7F\x0F\x25\x2B', 'LLIL_ADD.d(LLIL_REG.d(w27),LLIL_LSL.d(LLIL_ZX.d(LLIL_LOW_PART.b(LLIL_REG.d(w5))),LLIL_CONST.b(0x3)))'), # cmn w27, w5, uxtb #3
	# CMN_ADDS_64S_addsub_ext
	(b'\xBF\x0D\x2D\xAB', 'LLIL_ADD.q(LLIL_REG.q(x13),LLIL_LSL.q(LLIL_ZX.q(LLIL_LOW_PART.b(LLIL_REG.d(w13))),LLIL_CONST.b(0x3)))'), # cmn x13, w13, uxtb #3
	(b'\x3F\x65\x22\xAB', 'LLIL_ADD.q(LLIL_REG.q(x9),LLIL_LSL.q(LLIL_REG.q(x2),LLIL_CONST.b(0x1)))'), # cmn x9, x2, uxtx #1
	# does the add to 0 get optimized out?
	(b'\xDF\xA8\x3F\xAB', 'LLIL_REG.q(x6)'), # cmn x6, wzr, sxth #2
	(b'\x3F\x8B\x3E\xAB', 'LLIL_ADD.q(LLIL_REG.q(x25),LLIL_LSL.q(LLIL_SX.q(LLIL_LOW_PART.b(LLIL_REG.d(w30))),LLIL_CONST.b(0x2)))'), # cmn x25, w30, sxtb #2
	# CMP_SUBS_32S_addsub_ext
	(b'\x1F\x2B\x2D\x6B', 'LLIL_SUB.d(LLIL_REG.d(w24),LLIL_LSL.d(LLIL_ZX.d(LLIL_LOW_PART.w(LLIL_REG.d(w13))),LLIL_CONST.b(0x2)))'), # cmp w24, w13, uxth #2
	(b'\xBF\x51\x23\x6B', 'LLIL_SUB.d(LLIL_REG.d(w13),LLIL_LSL.d(LLIL_REG.d(w3),LLIL_CONST.b(0x4)))'), # cmp w13, w3, uxtw #4
	(b'\x1F\xD0\x31\x6B', 'LLIL_SUB.d(LLIL_REG.d(w0),LLIL_LSL.d(LLIL_REG.d(w17),LLIL_CONST.b(0x4)))'), # cmp w0, w17, sxtw #4
	(b'\xBF\x53\x3E\x6B', 'LLIL_SUB.d(LLIL_REG.d(w29),LLIL_LSL.d(LLIL_REG.d(w30),LLIL_CONST.b(0x4)))'), # cmp w29, w30, uxtw #4
	# CMP_SUBS_64S_addsub_ext
	(b'\x3F\x49\x22\xEB', 'LLIL_SUB.q(LLIL_REG.q(x9),LLIL_LSL.q(LLIL_ZX.q(LLIL_REG.d(w2)),LLIL_CONST.b(0x2)))'), # cmp x9, w2, uxtw #2
	(b'\xDF\x93\x31\xEB', 'LLIL_SUB.q(LLIL_REG.q(x30),LLIL_LSL.q(LLIL_SX.q(LLIL_LOW_PART.b(LLIL_REG.d(w17))),LLIL_CONST.b(0x4)))'), # cmp x30, w17, sxtb #4
	(b'\x7F\x87\x27\xEB', 'LLIL_SUB.q(LLIL_REG.q(x27),LLIL_LSL.q(LLIL_SX.q(LLIL_LOW_PART.b(LLIL_REG.d(w7))),LLIL_CONST.b(0x1)))'), # cmp x27, w7, sxtb #1
	(b'\x9F\xEC\x34\xEB', 'LLIL_SUB.q(LLIL_REG.q(x4),LLIL_LSL.q(LLIL_REG.q(x20),LLIL_CONST.b(0x3)))'), # cmp x4, x20, sxtx #3
	# SUBS_32S_addsub_ext
	(b'\xCD\xC9\x38\x6B', 'LLIL_SET_REG.d(w13,LLIL_SUB.d(LLIL_REG.d(w14),LLIL_LSL.d(LLIL_REG.d(w24),LLIL_CONST.b(0x2))))'), # subs w13, w14, w24, sxtw #2
	(b'\x72\xF0\x2B\x6B', 'LLIL_SET_REG.d(w18,LLIL_SUB.d(LLIL_REG.d(w3),LLIL_LSL.d(LLIL_SX.d(LLIL_REG.d(w11)),LLIL_CONST.b(0x4))))'), # subs w18, w3, w11, sxtx #4
	(b'\x77\xC1\x23\x6B', 'LLIL_SET_REG.d(w23,LLIL_SUB.d(LLIL_REG.d(w11),LLIL_REG.d(w3)))'), # subs w23, w11, w3, sxtw
	(b'\xD4\x47\x3F\x6B', 'LLIL_SET_REG.d(w20,LLIL_REG.d(w30))'), # subs w20, w30, wzr, uxtw #1
	# SUBS_64S_addsub_ext
	(b'\x26\x44\x3C\xEB', 'LLIL_SET_REG.q(x6,LLIL_SUB.q(LLIL_REG.q(x1),LLIL_LSL.q(LLIL_ZX.q(LLIL_REG.d(w28)),LLIL_CONST.b(0x1))))'), # subs x6, x1, w28, uxtw #1
	(b'\x8A\xE2\x2E\xEB', 'LLIL_SET_REG.q(x10,LLIL_SUB.q(LLIL_REG.q(x20),LLIL_REG.q(x14)))'), # subs x10, x20, x14, sxtx
	(b'\xC2\x4B\x3A\xEB', 'LLIL_SET_REG.q(x2,LLIL_SUB.q(LLIL_REG.q(x30),LLIL_LSL.q(LLIL_ZX.q(LLIL_REG.d(w26)),LLIL_CONST.b(0x2))))'), # subs x2, x30, w26, uxtw #2
	(b'\x04\x4A\x20\xEB', 'LLIL_SET_REG.q(x4,LLIL_SUB.q(LLIL_REG.q(x16),LLIL_LSL.q(LLIL_ZX.q(LLIL_REG.d(w0)),LLIL_CONST.b(0x2))))'), # subs x4, x16, w0, uxtw #2
	# SUB_32_addsub_ext
	(b'\x9E\x82\x2C\x4B', 'LLIL_SET_REG.d(w30,LLIL_SUB.d(LLIL_REG.d(w20),LLIL_SX.d(LLIL_LOW_PART.b(LLIL_REG.d(w12)))))'), # sub w30, w20, w12, sxtb
	(b'\xB9\x42\x32\x4B', 'LLIL_SET_REG.d(w25,LLIL_SUB.d(LLIL_REG.d(w21),LLIL_REG.d(w18)))'), # sub w25, w21, w18, uxtw
	(b'\xD9\x66\x3C\x4B', 'LLIL_SET_REG.d(w25,LLIL_SUB.d(LLIL_REG.d(w22),LLIL_LSL.d(LLIL_ZX.d(LLIL_REG.d(w28)),LLIL_CONST.b(0x1))))'), # sub w25, w22, w28, uxtx #1
	(b'\xCD\x4F\x22\x4B', 'LLIL_SET_REG.d(w13,LLIL_SUB.d(LLIL_REG.d(w30),LLIL_LSL.d(LLIL_REG.d(w2),LLIL_CONST.b(0x3))))'), # sub w13, w30, w2, uxtw #3
	# SUB_64_addsub_ext
	(b'\xF7\x8D\x3F\xCB', 'LLIL_SET_REG.q(x23,LLIL_REG.q(x15))'), # sub x23, x15, wzr, sxtb #3
	(b'\xFF\x64\x27\xCB', 'LLIL_SET_REG.q(sp,LLIL_SUB.q(LLIL_REG.q(x7),LLIL_LSL.q(LLIL_REG.q(x7),LLIL_CONST.b(0x1))))'), # sub sp, x7, x7, lsl #1
	(b'\xA5\x23\x23\xCB', 'LLIL_SET_REG.q(x5,LLIL_SUB.q(LLIL_REG.q(x29),LLIL_ZX.q(LLIL_LOW_PART.w(LLIL_REG.d(w3)))))'), # sub x5, x29, w3, uxth
	(b'\xA4\x69\x37\xCB', 'LLIL_SET_REG.q(x4,LLIL_SUB.q(LLIL_REG.q(x13),LLIL_LSL.q(LLIL_REG.q(x23),LLIL_CONST.b(0x2))))'), # sub x4, x13, x23, uxtx #2
	(b'\x21\xf0\x9f\xf8', 'LLIL_INTRINSIC([],__prefetch,LLIL_CALL_PARAM([LLIL_LOAD.q(LLIL_ADD.q(LLIL_REG.q(x1),LLIL_CONST.q(0xFFFFFFFFFFFFFFFF)))]))'), # prfum pldl1strm, [x1, #-0x1]
	(b'\x21\x00\x80\xf9', 'LLIL_INTRINSIC([],__prefetch,LLIL_CALL_PARAM([LLIL_LOAD.q(LLIL_REG.q(x1))]))'), # prfm pldl1strm, [x1]
	(b'\x24\x98\x41\xba', 'LLIL_IF(LLIL_OR(LLIL_FLAG(z),LLIL_FLAG(c)),1,3); LLIL_ADD.q(LLIL_REG.q(x1),LLIL_CONST.q(0x1)); LLIL_GOTO(8); LLIL_SET_FLAG(n,LLIL_CONST(0)); LLIL_SET_FLAG(z,LLIL_CONST(1)); LLIL_SET_FLAG(c,LLIL_CONST(0)); LLIL_SET_FLAG(v,LLIL_CONST(0)); LLIL_GOTO(8)'), # ccmn x1, #0x1, #0x4, ls
	(b'\x41\x7c\xc3\x9b', 'LLIL_SET_REG.q(x1,LLIL_LSR.128(LLIL_MULU_DP.q(LLIL_REG.q(x2),LLIL_REG.q(x3)),LLIL_CONST.b(0x8)))'), # umulh x1, x2, x3
	(b'\x41\x7c\x43\x9b', 'LLIL_SET_REG.q(x1,LLIL_LSR.128(LLIL_MULS_DP.q(LLIL_REG.q(x2),LLIL_REG.q(x3)),LLIL_CONST.b(0x8)))'), # smulh x1, x2, x3
	(b'\x41\x7c\x23\x9b', 'LLIL_SET_REG.q(x1,LLIL_MULS_DP.q(LLIL_REG.d(w2),LLIL_REG.d(w3)))'), # smull x1, w2, w3
	(b'\x41\x7c\xa3\x9b', 'LLIL_SET_REG.q(x1,LLIL_MULU_DP.q(LLIL_REG.d(w2),LLIL_REG.d(w3)))'), # umull x1, w2, w3
	(b'\x41\x00\x03\x8b', 'LLIL_SET_REG.q(x1,LLIL_ADD.q(LLIL_REG.q(x2),LLIL_REG.q(x3)))'), # add x1,x2,x3
	(b'\x41\x00\x03\xab', 'LLIL_SET_REG.q(x1,LLIL_ADD.q(LLIL_REG.q(x2),LLIL_REG.q(x3)))'), # adds x1,x2,x3 with IL_FLAGWRITE_ALL
	(b'\x41\x00\x03\x8a', 'LLIL_SET_REG.q(x1,LLIL_AND.q(LLIL_REG.q(x2),LLIL_REG.q(x3)))'), # and x1,x2,x3
	(b'\x41\x00\x03\xea', 'LLIL_SET_REG.q(x1,LLIL_AND.q(LLIL_REG.q(x2),LLIL_REG.q(x3)))'), # ands x1,x2,x3 with IL_FLAGWRITE_ALL
	(b'\x41\x00\x03\xda', 'LLIL_SET_REG.q(x1,LLIL_SBB.q(LLIL_REG.q(x2),LLIL_REG.q(x3),LLIL_NOT(LLIL_FLAG(c))))'), # sbc x1,x2,x3
	(b'\x41\x00\x03\xfa', 'LLIL_SET_REG.q(x1,LLIL_SBB.q(LLIL_REG.q(x2),LLIL_REG.q(x3),LLIL_NOT(LLIL_FLAG(c))))'), # sbcs x1,x2,x3 with IL_FLAGWRITE_ALL
	(b'\x01\x00\x00\xd4', 'LLIL_SET_REG.w(syscall_imm,LLIL_CONST.w(0x0)); LLIL_SYSCALL()'), # svc #0; ret; ZwAccessCheck() on win-arm64
	(b'\x21\x00\x00\xd4', 'LLIL_SET_REG.w(syscall_imm,LLIL_CONST.w(0x1)); LLIL_SYSCALL()'), # svc #1; ret; ZwWorkerFactoryWorkerReady() on win-arm64
	(b'\x41\x00\x00\xd4', 'LLIL_SET_REG.w(syscall_imm,LLIL_CONST.w(0x2)); LLIL_SYSCALL()'), # svc #2; ret; ZwAcceptConnectPort() on win-arm64
	(b'\x61\x00\x00\xd4', 'LLIL_SET_REG.w(syscall_imm,LLIL_CONST.w(0x3)); LLIL_SYSCALL()'), # svc #3; ret; ZwMapUserPhysicalPagesScatter() on win-arm64
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
	#(b'\xdf\x20\x03\xd5', 'LLIL_INTRINSIC([],SystemHintOp_DGH,LLIL_CALL_PARAM([]))'), # hint 0x6 - now ARM64_DGH
	#(b'\x1f\x22\x03\xd5', 'LLIL_INTRINSIC([],SystemHintOp_ESB,LLIL_CALL_PARAM([]))'), # hint 0x10 - now ARM64_ESB
	#(b'\x3f\x22\x03\xd5', 'LLIL_INTRINSIC([],SystemHintOp_PSB,LLIL_CALL_PARAM([]))'), # hint 0x11 - now ARM64_PSB
	#(b'\x5f\x22\x03\xd5', 'LLIL_INTRINSIC([],SystemHintOp_TSB,LLIL_CALL_PARAM([]))'), # hint 0x12 - now ARM64_TSB
	#(b'\x9f\x22\x03\xd5', 'LLIL_INTRINSIC([],SystemHintOp_CSDB,LLIL_CALL_PARAM([]))'), # hint 0x14 - now ARM64_CSDB
	#(b'\x5f\x24\x03\xd5', 'LLIL_INTRINSIC([],SystemHintOp_BTI,LLIL_CALL_PARAM([]))'), # hint 0x22 - now ARM64_BTI
	(b'\x00\xc0\x1e\xd5', 'LLIL_INTRINSIC([vbar_el3],_WriteStatusReg,LLIL_CALL_PARAM([LLIL_REG.q(x0)]))'), # msr vbar_el3, x0
	(b'\x00\x10\x1e\xd5', 'LLIL_INTRINSIC([sctlr_el3],_WriteStatusReg,LLIL_CALL_PARAM([LLIL_REG.q(x0)]))'), # msr sctlr_el3, x0
#	(b'\xff\x44\x03\xd5', 'LLIL_INTRINSIC([daifclr],_WriteStatusReg,LLIL_CALL_PARAM([LLIL_CONST.d(0x4)]))'), # msr daifclr, #0x4
	(b'\x00\x10\x3e\xd5', 'LLIL_INTRINSIC([x0],_ReadStatusReg,LLIL_CALL_PARAM([LLIL_REG(sctlr_el3)]))'), # mrs x0, sctlr_el3
	(b'\xC1\x48\x52\x7A', 'LLIL_IF(LLIL_FLAG(n),1,3); LLIL_SUB.d(LLIL_REG.d(w6),LLIL_CONST.d(0x12)); LLIL_GOTO(8); LLIL_SET_FLAG(n,LLIL_CONST(0)); LLIL_SET_FLAG(z,LLIL_CONST(0)); LLIL_SET_FLAG(c,LLIL_CONST(0)); LLIL_SET_FLAG(v,LLIL_CONST(1)); LLIL_GOTO(8)'), # ccmp w6, #18, #1, mi
#	# this is funky: LLIL_SUB() is optmized away, and we needed it for the IL_FLAGWRITE_ALL, did it have effect?
	(b'\x62\x08\x40\x7A', 'LLIL_IF(LLIL_FLAG(z),1,3); LLIL_REG.d(w3); LLIL_GOTO(8); LLIL_SET_FLAG(n,LLIL_CONST(0)); LLIL_SET_FLAG(z,LLIL_CONST(0)); LLIL_SET_FLAG(c,LLIL_CONST(1)); LLIL_SET_FLAG(v,LLIL_CONST(0)); LLIL_GOTO(8)'), # ccmp w3, #0, #2, eq
	(b'\x43\xBA\x59\x7A', 'LLIL_IF(LLIL_CMP_NE(LLIL_FLAG(n),LLIL_FLAG(v)),1,3); LLIL_SUB.d(LLIL_REG.d(w18),LLIL_CONST.d(0x19)); LLIL_GOTO(8); LLIL_SET_FLAG(n,LLIL_CONST(0)); LLIL_SET_FLAG(z,LLIL_CONST(0)); LLIL_SET_FLAG(c,LLIL_CONST(1)); LLIL_SET_FLAG(v,LLIL_CONST(1)); LLIL_GOTO(8)'), # ccmp w18, #25, #3, lt
	(b'\xC4\x29\x5B\x7A', 'LLIL_IF(LLIL_NOT(LLIL_FLAG(c)),1,3); LLIL_SUB.d(LLIL_REG.d(w14),LLIL_CONST.d(0x1B)); LLIL_GOTO(8); LLIL_SET_FLAG(n,LLIL_CONST(0)); LLIL_SET_FLAG(z,LLIL_CONST(1)); LLIL_SET_FLAG(c,LLIL_CONST(0)); LLIL_SET_FLAG(v,LLIL_CONST(0)); LLIL_GOTO(8)'), # ccmp w14, #27, #4, hs
	(b'\x24\x08\x5B\x7A', 'LLIL_IF(LLIL_FLAG(z),1,3); LLIL_SUB.d(LLIL_REG.d(w1),LLIL_CONST.d(0x1B)); LLIL_GOTO(8); LLIL_SET_FLAG(n,LLIL_CONST(0)); LLIL_SET_FLAG(z,LLIL_CONST(1)); LLIL_SET_FLAG(c,LLIL_CONST(0)); LLIL_SET_FLAG(v,LLIL_CONST(0)); LLIL_GOTO(8)'), # ccmp w1, #27, #4, eq
	(b'\x22\x6A\x41\x7A', 'LLIL_IF(LLIL_FLAG(v),1,3); LLIL_SUB.d(LLIL_REG.d(w17),LLIL_CONST.d(0x1)); LLIL_GOTO(8); LLIL_SET_FLAG(n,LLIL_CONST(0)); LLIL_SET_FLAG(z,LLIL_CONST(0)); LLIL_SET_FLAG(c,LLIL_CONST(1)); LLIL_SET_FLAG(v,LLIL_CONST(0)); LLIL_GOTO(8)'), # ccmp w17, #1, #2, vs
	(b'\xA8\xA8\x41\x7A', 'LLIL_IF(LLIL_CMP_E(LLIL_FLAG(n),LLIL_FLAG(v)),1,3); LLIL_SUB.d(LLIL_REG.d(w5),LLIL_CONST.d(0x1)); LLIL_GOTO(8); LLIL_SET_FLAG(n,LLIL_CONST(1)); LLIL_SET_FLAG(z,LLIL_CONST(0)); LLIL_SET_FLAG(c,LLIL_CONST(0)); LLIL_SET_FLAG(v,LLIL_CONST(0)); LLIL_GOTO(8)'), # ccmp w5, #1, #8, ge
	(b'\x08\x49\x5E\x7A', 'LLIL_IF(LLIL_FLAG(n),1,3); LLIL_SUB.d(LLIL_REG.d(w8),LLIL_CONST.d(0x1E)); LLIL_GOTO(8); LLIL_SET_FLAG(n,LLIL_CONST(1)); LLIL_SET_FLAG(z,LLIL_CONST(0)); LLIL_SET_FLAG(c,LLIL_CONST(0)); LLIL_SET_FLAG(v,LLIL_CONST(0)); LLIL_GOTO(8)'), # ccmp w8, #30, #8, mi
	(b'\x0a\x00\x80\x52', 'LLIL_SET_REG.d(w10,LLIL_CONST.d(0x0))'), # mov 10, #0
	(b'\x1f\x20\x03\xd5', ''), # nop, gets optimized from function
]

import re
import sys
import binaryninja
from binaryninja import binaryview
from binaryninja import lowlevelil
from binaryninja.enums import LowLevelILOperation

def il2str(il):
	sz_lookup = {1:'.b', 2:'.w', 4:'.d', 8:'.q', 16:'.128'}
	if isinstance(il, lowlevelil.LowLevelILInstruction):
		size_suffix = sz_lookup.get(il.size, '?') if il.size else ''
		# print size-specified IL constants in hex
		if il.operation in [LowLevelILOperation.LLIL_CONST, LowLevelILOperation.LLIL_CONST_PTR] and il.size:
			tmp = il.operands[0]
			if tmp < 0: tmp = (1<<(il.size*8))+tmp
			tmp = '0x%X' % tmp if il.size else '%d' % il.size
			return 'LLIL_CONST%s(%s)' % (size_suffix, tmp)
		else:
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
	if result.endswith('LLIL_RET(LLIL_REG.q(x30))'):
		result = result[0:result.index('LLIL_RET(LLIL_REG.q(x30))')]
	if result.endswith('; '):
		result = result[0:-2]

	return result

def il_str_to_tree(ilstr):
	result = ''
	depth = 0
	for c in ilstr:
		if c == '(':
			result += '\n'
			depth += 1
			result += '    '*depth
		elif c == ')':
			depth -= 1
		elif c == ',':
			result += '\n'
			result += '    '*depth
			pass
		else:
			result += c
	return result

def test_all():
	for (test_i, (data, expected)) in enumerate(test_cases):
		actual = instr_to_il(data)
		if actual != expected:
			print('MISMATCH AT TEST %d!' % test_i)
			print('\t   input: %s' % data.hex())
			print('\texpected: %s' % expected)
			print('\t  actual: %s' % actual)
			print('\t    tree:')
			print(il_str_to_tree(actual))

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

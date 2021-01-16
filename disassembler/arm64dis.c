#include <stdbool.h>
#include <string.h>
#include <stdio.h>
#include <stdint.h>
#include <inttypes.h>

#include "sysregs.h"
#include "operations.h"
#include "encodings.h"
#include "arm64dis.h"
#include "pcode.h"

//-----------------------------------------------------------------------------
// registers (non-system)
//-----------------------------------------------------------------------------

static const char *RegisterString[] =
{
	"NONE",
	"w0",  "w1",  "w2",  "w3",  "w4",  "w5",  "w6",  "w7",
	"w8",  "w9",  "w10", "w11", "w12", "w13", "w14", "w15",
	"w16", "w17", "w18", "w19", "w20", "w21", "w22", "w23",
	"w24", "w25", "w26", "w27", "w28", "w29", "w30", "wzr", "wsp",
	"x0",  "x1",  "x2",  "x3",  "x4",  "x5",  "x6",  "x7",
	"x8",  "x9",  "x10", "x11", "x12", "x13", "x14", "x15",
	"x16", "x17", "x18", "x19", "x20", "x21", "x22", "x23",
	"x24", "x25", "x26", "x27", "x28", "x29", "x30", "xzr", "sp",
	"v0",  "v1",  "v2",  "v3",  "v4",  "v5",  "v6",  "v7",
	"v8",  "v9",  "v10", "v11", "v12", "v13", "v14", "v15",
	"v16", "v17", "v18", "v19", "v20", "v21", "v22", "v23",
	"v24", "v25", "v26", "v27", "v28", "v29", "v30", "v31", "v31",
	"b0",  "b1",  "b2",  "b3",  "b4",  "b5",  "b6",  "b7",
	"b8",  "b9",  "b10", "b11", "b12", "b13", "b14", "b15",
	"b16", "b17", "b18", "b19", "b20", "b21", "b22", "b23",
	"b24", "b25", "b26", "b27", "b28", "b29", "b30", "b31", "b31",
	"h0",  "h1",  "h2",  "h3",  "h4",  "h5",  "h6",  "h7",
	"h8",  "h9",  "h10", "h11", "h12", "h13", "h14", "h15",
	"h16", "h17", "h18", "h19", "h20", "h21", "h22", "h23",
	"h24", "h25", "h26", "h27", "h28", "h29", "h30", "h31", "h31",
	"s0",  "s1",  "s2",  "s3",  "s4",  "s5",  "s6",  "s7",
	"s8",  "s9",  "s10", "s11", "s12", "s13", "s14", "s15",
	"s16", "s17", "s18", "s19", "s20", "s21", "s22", "s23",
	"s24", "s25", "s26", "s27", "s28", "s29", "s30", "s31", "s31",
	"d0",  "d1",  "d2",  "d3",  "d4",  "d5",  "d6",  "d7",
	"d8",  "d9",  "d10", "d11", "d12", "d13", "d14", "d15",
	"d16", "d17", "d18", "d19", "d20", "d21", "d22", "d23",
	"d24", "d25", "d26", "d27", "d28", "d29", "d30", "d31", "d31",
	"q0",  "q1",  "q2",  "q3",  "q4",  "q5",  "q6",  "q7",
	"q8",  "q9",  "q10", "q11", "q12", "q13", "q14", "q15",
	"q16", "q17", "q18", "q19", "q20", "q21", "q22", "q23",
	"q24", "q25", "q26", "q27", "q28", "q29", "q30", "q31", "q31",
	// B vectors
	"v0.b[0]", "v0.b[1]", "v0.b[2]", "v0.b[3]", "v0.b[4]", "v0.b[5]", "v0.b[6]", "v0.b[7]",
	"v0.b[8]", "v0.b[9]", "v0.b[10]", "v0.b[11]", "v0.b[12]", "v0.b[13]", "v0.b[14]", "v0.b[15]",
	"v1.b[0]", "v1.b[1]", "v1.b[2]", "v1.b[3]", "v1.b[4]", "v1.b[5]", "v1.b[6]", "v1.b[7]",
	"v1.b[8]", "v1.b[9]", "v1.b[10]", "v1.b[11]", "v1.b[12]", "v1.b[13]", "v1.b[14]", "v1.b[15]",
	"v2.b[0]", "v2.b[1]", "v2.b[2]", "v2.b[3]", "v2.b[4]", "v2.b[5]", "v2.b[6]", "v2.b[7]",
	"v2.b[8]", "v2.b[9]", "v2.b[10]", "v2.b[11]", "v2.b[12]", "v2.b[13]", "v2.b[14]", "v2.b[15]",
	"v3.b[0]", "v3.b[1]", "v3.b[2]", "v3.b[3]", "v3.b[4]", "v3.b[5]", "v3.b[6]", "v3.b[7]",
	"v3.b[8]", "v3.b[9]", "v3.b[10]", "v3.b[11]", "v3.b[12]", "v3.b[13]", "v3.b[14]", "v3.b[15]",
	"v4.b[0]", "v4.b[1]", "v4.b[2]", "v4.b[3]", "v4.b[4]", "v4.b[5]", "v4.b[6]", "v4.b[7]",
	"v4.b[8]", "v4.b[9]", "v4.b[10]", "v4.b[11]", "v4.b[12]", "v4.b[13]", "v4.b[14]", "v4.b[15]",
	"v5.b[0]", "v5.b[1]", "v5.b[2]", "v5.b[3]", "v5.b[4]", "v5.b[5]", "v5.b[6]", "v5.b[7]",
	"v5.b[8]", "v5.b[9]", "v5.b[10]", "v5.b[11]", "v5.b[12]", "v5.b[13]", "v5.b[14]", "v5.b[15]",
	"v6.b[0]", "v6.b[1]", "v6.b[2]", "v6.b[3]", "v6.b[4]", "v6.b[5]", "v6.b[6]", "v6.b[7]",
	"v6.b[8]", "v6.b[9]", "v6.b[10]", "v6.b[11]", "v6.b[12]", "v6.b[13]", "v6.b[14]", "v6.b[15]",
	"v7.b[0]", "v7.b[1]", "v7.b[2]", "v7.b[3]", "v7.b[4]", "v7.b[5]", "v7.b[6]", "v7.b[7]",
	"v7.b[8]", "v7.b[9]", "v7.b[10]", "v7.b[11]", "v7.b[12]", "v7.b[13]", "v7.b[14]", "v7.b[15]",
	"v8.b[0]", "v8.b[1]", "v8.b[2]", "v8.b[3]", "v8.b[4]", "v8.b[5]", "v8.b[6]", "v8.b[7]",
	"v8.b[8]", "v8.b[9]", "v8.b[10]", "v8.b[11]", "v8.b[12]", "v8.b[13]", "v8.b[14]", "v8.b[15]",
	"v9.b[0]", "v9.b[1]", "v9.b[2]", "v9.b[3]", "v9.b[4]", "v9.b[5]", "v9.b[6]", "v9.b[7]",
	"v9.b[8]", "v9.b[9]", "v9.b[10]", "v9.b[11]", "v9.b[12]", "v9.b[13]", "v9.b[14]", "v9.b[15]",
	"v10.b[0]", "v10.b[1]", "v10.b[2]", "v10.b[3]", "v10.b[4]", "v10.b[5]", "v10.b[6]", "v10.b[7]",
	"v10.b[8]", "v10.b[9]", "v10.b[10]", "v10.b[11]", "v10.b[12]", "v10.b[13]", "v10.b[14]", "v10.b[15]",
	"v11.b[0]", "v11.b[1]", "v11.b[2]", "v11.b[3]", "v11.b[4]", "v11.b[5]", "v11.b[6]", "v11.b[7]",
	"v11.b[8]", "v11.b[9]", "v11.b[10]", "v11.b[11]", "v11.b[12]", "v11.b[13]", "v11.b[14]", "v11.b[15]",
	"v12.b[0]", "v12.b[1]", "v12.b[2]", "v12.b[3]", "v12.b[4]", "v12.b[5]", "v12.b[6]", "v12.b[7]",
	"v12.b[8]", "v12.b[9]", "v12.b[10]", "v12.b[11]", "v12.b[12]", "v12.b[13]", "v12.b[14]", "v12.b[15]",
	"v13.b[0]", "v13.b[1]", "v13.b[2]", "v13.b[3]", "v13.b[4]", "v13.b[5]", "v13.b[6]", "v13.b[7]",
	"v13.b[8]", "v13.b[9]", "v13.b[10]", "v13.b[11]", "v13.b[12]", "v13.b[13]", "v13.b[14]", "v13.b[15]",
	"v14.b[0]", "v14.b[1]", "v14.b[2]", "v14.b[3]", "v14.b[4]", "v14.b[5]", "v14.b[6]", "v14.b[7]",
	"v14.b[8]", "v14.b[9]", "v14.b[10]", "v14.b[11]", "v14.b[12]", "v14.b[13]", "v14.b[14]", "v14.b[15]",
	"v15.b[0]", "v15.b[1]", "v15.b[2]", "v15.b[3]", "v15.b[4]", "v15.b[5]", "v15.b[6]", "v15.b[7]",
	"v15.b[8]", "v15.b[9]", "v15.b[10]", "v15.b[11]", "v15.b[12]", "v15.b[13]", "v15.b[14]", "v15.b[15]",
	"v16.b[0]", "v16.b[1]", "v16.b[2]", "v16.b[3]", "v16.b[4]", "v16.b[5]", "v16.b[6]", "v16.b[7]",
	"v16.b[8]", "v16.b[9]", "v16.b[10]", "v16.b[11]", "v16.b[12]", "v16.b[13]", "v16.b[14]", "v16.b[15]",
	"v17.b[0]", "v17.b[1]", "v17.b[2]", "v17.b[3]", "v17.b[4]", "v17.b[5]", "v17.b[6]", "v17.b[7]",
	"v17.b[8]", "v17.b[9]", "v17.b[10]", "v17.b[11]", "v17.b[12]", "v17.b[13]", "v17.b[14]", "v17.b[15]",
	"v18.b[0]", "v18.b[1]", "v18.b[2]", "v18.b[3]", "v18.b[4]", "v18.b[5]", "v18.b[6]", "v18.b[7]",
	"v18.b[8]", "v18.b[9]", "v18.b[10]", "v18.b[11]", "v18.b[12]", "v18.b[13]", "v18.b[14]", "v18.b[15]",
	"v19.b[0]", "v19.b[1]", "v19.b[2]", "v19.b[3]", "v19.b[4]", "v19.b[5]", "v19.b[6]", "v19.b[7]",
	"v19.b[8]", "v19.b[9]", "v19.b[10]", "v19.b[11]", "v19.b[12]", "v19.b[13]", "v19.b[14]", "v19.b[15]",
	"v20.b[0]", "v20.b[1]", "v20.b[2]", "v20.b[3]", "v20.b[4]", "v20.b[5]", "v20.b[6]", "v20.b[7]",
	"v20.b[8]", "v20.b[9]", "v20.b[10]", "v20.b[11]", "v20.b[12]", "v20.b[13]", "v20.b[14]", "v20.b[15]",
	"v21.b[0]", "v21.b[1]", "v21.b[2]", "v21.b[3]", "v21.b[4]", "v21.b[5]", "v21.b[6]", "v21.b[7]",
	"v21.b[8]", "v21.b[9]", "v21.b[10]", "v21.b[11]", "v21.b[12]", "v21.b[13]", "v21.b[14]", "v21.b[15]",
	"v22.b[0]", "v22.b[1]", "v22.b[2]", "v22.b[3]", "v22.b[4]", "v22.b[5]", "v22.b[6]", "v22.b[7]",
	"v22.b[8]", "v22.b[9]", "v22.b[10]", "v22.b[11]", "v22.b[12]", "v22.b[13]", "v22.b[14]", "v22.b[15]",
	"v23.b[0]", "v23.b[1]", "v23.b[2]", "v23.b[3]", "v23.b[4]", "v23.b[5]", "v23.b[6]", "v23.b[7]",
	"v23.b[8]", "v23.b[9]", "v23.b[10]", "v23.b[11]", "v23.b[12]", "v23.b[13]", "v23.b[14]", "v23.b[15]",
	"v24.b[0]", "v24.b[1]", "v24.b[2]", "v24.b[3]", "v24.b[4]", "v24.b[5]", "v24.b[6]", "v24.b[7]",
	"v24.b[8]", "v24.b[9]", "v24.b[10]", "v24.b[11]", "v24.b[12]", "v24.b[13]", "v24.b[14]", "v24.b[15]",
	"v25.b[0]", "v25.b[1]", "v25.b[2]", "v25.b[3]", "v25.b[4]", "v25.b[5]", "v25.b[6]", "v25.b[7]",
	"v25.b[8]", "v25.b[9]", "v25.b[10]", "v25.b[11]", "v25.b[12]", "v25.b[13]", "v25.b[14]", "v25.b[15]",
	"v26.b[0]", "v26.b[1]", "v26.b[2]", "v26.b[3]", "v26.b[4]", "v26.b[5]", "v26.b[6]", "v26.b[7]",
	"v26.b[8]", "v26.b[9]", "v26.b[10]", "v26.b[11]", "v26.b[12]", "v26.b[13]", "v26.b[14]", "v26.b[15]",
	"v27.b[0]", "v27.b[1]", "v27.b[2]", "v27.b[3]", "v27.b[4]", "v27.b[5]", "v27.b[6]", "v27.b[7]",
	"v27.b[8]", "v27.b[9]", "v27.b[10]", "v27.b[11]", "v27.b[12]", "v27.b[13]", "v27.b[14]", "v27.b[15]",
	"v28.b[0]", "v28.b[1]", "v28.b[2]", "v28.b[3]", "v28.b[4]", "v28.b[5]", "v28.b[6]", "v28.b[7]",
	"v28.b[8]", "v28.b[9]", "v28.b[10]", "v28.b[11]", "v28.b[12]", "v28.b[13]", "v28.b[14]", "v28.b[15]",
	"v29.b[0]", "v29.b[1]", "v29.b[2]", "v29.b[3]", "v29.b[4]", "v29.b[5]", "v29.b[6]", "v29.b[7]",
	"v29.b[8]", "v29.b[9]", "v29.b[10]", "v29.b[11]", "v29.b[12]", "v29.b[13]", "v29.b[14]", "v29.b[15]",
	"v30.b[0]", "v30.b[1]", "v30.b[2]", "v30.b[3]", "v30.b[4]", "v30.b[5]", "v30.b[6]", "v30.b[7]",
	"v30.b[8]", "v30.b[9]", "v30.b[10]", "v30.b[11]", "v30.b[12]", "v30.b[13]", "v30.b[14]", "v30.b[15]",
	"v31.b[0]", "v31.b[1]", "v31.b[2]", "v31.b[3]", "v31.b[4]", "v31.b[5]", "v31.b[6]", "v31.b[7]",
	"v31.b[8]", "v31.b[9]", "v31.b[10]", "v31.b[11]", "v31.b[12]", "v31.b[13]", "v31.b[14]", "v31.b[15]",
	// H vectors
	"v0.h[0]", "v0.h[1]", "v0.h[2]", "v0.h[3]", "v0.h[4]", "v0.h[5]", "v0.h[6]", "v0.h[7]",
	"v1.h[0]", "v1.h[1]", "v1.h[2]", "v1.h[3]", "v1.h[4]", "v1.h[5]", "v1.h[6]", "v1.h[7]",
	"v2.h[0]", "v2.h[1]", "v2.h[2]", "v2.h[3]", "v2.h[4]", "v2.h[5]", "v2.h[6]", "v2.h[7]",
	"v3.h[0]", "v3.h[1]", "v3.h[2]", "v3.h[3]", "v3.h[4]", "v3.h[5]", "v3.h[6]", "v3.h[7]",
	"v4.h[0]", "v4.h[1]", "v4.h[2]", "v4.h[3]", "v4.h[4]", "v4.h[5]", "v4.h[6]", "v4.h[7]",
	"v5.h[0]", "v5.h[1]", "v5.h[2]", "v5.h[3]", "v5.h[4]", "v5.h[5]", "v5.h[6]", "v5.h[7]",
	"v6.h[0]", "v6.h[1]", "v6.h[2]", "v6.h[3]", "v6.h[4]", "v6.h[5]", "v6.h[6]", "v6.h[7]",
	"v7.h[0]", "v7.h[1]", "v7.h[2]", "v7.h[3]", "v7.h[4]", "v7.h[5]", "v7.h[6]", "v7.h[7]",
	"v8.h[0]", "v8.h[1]", "v8.h[2]", "v8.h[3]", "v8.h[4]", "v8.h[5]", "v8.h[6]", "v8.h[7]",
	"v9.h[0]", "v9.h[1]", "v9.h[2]", "v9.h[3]", "v9.h[4]", "v9.h[5]", "v9.h[6]", "v9.h[7]",
	"v10.h[0]", "v10.h[1]", "v10.h[2]", "v10.h[3]", "v10.h[4]", "v10.h[5]", "v10.h[6]", "v10.h[7]",
	"v11.h[0]", "v11.h[1]", "v11.h[2]", "v11.h[3]", "v11.h[4]", "v11.h[5]", "v11.h[6]", "v11.h[7]",
	"v12.h[0]", "v12.h[1]", "v12.h[2]", "v12.h[3]", "v12.h[4]", "v12.h[5]", "v12.h[6]", "v12.h[7]",
	"v13.h[0]", "v13.h[1]", "v13.h[2]", "v13.h[3]", "v13.h[4]", "v13.h[5]", "v13.h[6]", "v13.h[7]",
	"v14.h[0]", "v14.h[1]", "v14.h[2]", "v14.h[3]", "v14.h[4]", "v14.h[5]", "v14.h[6]", "v14.h[7]",
	"v15.h[0]", "v15.h[1]", "v15.h[2]", "v15.h[3]", "v15.h[4]", "v15.h[5]", "v15.h[6]", "v15.h[7]",
	"v16.h[0]", "v16.h[1]", "v16.h[2]", "v16.h[3]", "v16.h[4]", "v16.h[5]", "v16.h[6]", "v16.h[7]",
	"v17.h[0]", "v17.h[1]", "v17.h[2]", "v17.h[3]", "v17.h[4]", "v17.h[5]", "v17.h[6]", "v17.h[7]",
	"v18.h[0]", "v18.h[1]", "v18.h[2]", "v18.h[3]", "v18.h[4]", "v18.h[5]", "v18.h[6]", "v18.h[7]",
	"v19.h[0]", "v19.h[1]", "v19.h[2]", "v19.h[3]", "v19.h[4]", "v19.h[5]", "v19.h[6]", "v19.h[7]",
	"v20.h[0]", "v20.h[1]", "v20.h[2]", "v20.h[3]", "v20.h[4]", "v20.h[5]", "v20.h[6]", "v20.h[7]",
	"v21.h[0]", "v21.h[1]", "v21.h[2]", "v21.h[3]", "v21.h[4]", "v21.h[5]", "v21.h[6]", "v21.h[7]",
	"v22.h[0]", "v22.h[1]", "v22.h[2]", "v22.h[3]", "v22.h[4]", "v22.h[5]", "v22.h[6]", "v22.h[7]",
	"v23.h[0]", "v23.h[1]", "v23.h[2]", "v23.h[3]", "v23.h[4]", "v23.h[5]", "v23.h[6]", "v23.h[7]",
	"v24.h[0]", "v24.h[1]", "v24.h[2]", "v24.h[3]", "v24.h[4]", "v24.h[5]", "v24.h[6]", "v24.h[7]",
	"v25.h[0]", "v25.h[1]", "v25.h[2]", "v25.h[3]", "v25.h[4]", "v25.h[5]", "v25.h[6]", "v25.h[7]",
	"v26.h[0]", "v26.h[1]", "v26.h[2]", "v26.h[3]", "v26.h[4]", "v26.h[5]", "v26.h[6]", "v26.h[7]",
	"v27.h[0]", "v27.h[1]", "v27.h[2]", "v27.h[3]", "v27.h[4]", "v27.h[5]", "v27.h[6]", "v27.h[7]",
	"v28.h[0]", "v28.h[1]", "v28.h[2]", "v28.h[3]", "v28.h[4]", "v28.h[5]", "v28.h[6]", "v28.h[7]",
	"v29.h[0]", "v29.h[1]", "v29.h[2]", "v29.h[3]", "v29.h[4]", "v29.h[5]", "v29.h[6]", "v29.h[7]",
	"v30.h[0]", "v30.h[1]", "v30.h[2]", "v30.h[3]", "v30.h[4]", "v30.h[5]", "v30.h[6]", "v30.h[7]",
	"v31.h[0]", "v31.h[1]", "v31.h[2]", "v31.h[3]", "v31.h[4]", "v31.h[5]", "v31.h[6]", "v31.h[7]",
	// S vectors
	"v0.s[0]", "v0.s[1]", "v0.s[2]", "v0.s[3]", "v1.s[0]", "v1.s[1]", "v1.s[2]", "v1.s[3]",
	"v2.s[0]", "v2.s[1]", "v2.s[2]", "v2.s[3]", "v3.s[0]", "v3.s[1]", "v3.s[2]", "v3.s[3]",
	"v4.s[0]", "v4.s[1]", "v4.s[2]", "v4.s[3]", "v5.s[0]", "v5.s[1]", "v5.s[2]", "v5.s[3]",
	"v6.s[0]", "v6.s[1]", "v6.s[2]", "v6.s[3]", "v7.s[0]", "v7.s[1]", "v7.s[2]", "v7.s[3]",
	"v8.s[0]", "v8.s[1]", "v8.s[2]", "v8.s[3]", "v9.s[0]", "v9.s[1]", "v9.s[2]", "v9.s[3]",
	"v10.s[0]", "v10.s[1]", "v10.s[2]", "v10.s[3]", "v11.s[0]", "v11.s[1]", "v11.s[2]", "v11.s[3]",
	"v12.s[0]", "v12.s[1]", "v12.s[2]", "v12.s[3]", "v13.s[0]", "v13.s[1]", "v13.s[2]", "v13.s[3]",
	"v14.s[0]", "v14.s[1]", "v14.s[2]", "v14.s[3]", "v15.s[0]", "v15.s[1]", "v15.s[2]", "v15.s[3]",
	"v16.s[0]", "v16.s[1]", "v16.s[2]", "v16.s[3]", "v17.s[0]", "v17.s[1]", "v17.s[2]", "v17.s[3]",
	"v18.s[0]", "v18.s[1]", "v18.s[2]", "v18.s[3]", "v19.s[0]", "v19.s[1]", "v19.s[2]", "v19.s[3]",
	"v20.s[0]", "v20.s[1]", "v20.s[2]", "v20.s[3]", "v21.s[0]", "v21.s[1]", "v21.s[2]", "v21.s[3]",
	"v22.s[0]", "v22.s[1]", "v22.s[2]", "v22.s[3]", "v23.s[0]", "v23.s[1]", "v23.s[2]", "v23.s[3]",
	"v24.s[0]", "v24.s[1]", "v24.s[2]", "v24.s[3]", "v25.s[0]", "v25.s[1]", "v25.s[2]", "v25.s[3]",
	"v26.s[0]", "v26.s[1]", "v26.s[2]", "v26.s[3]", "v27.s[0]", "v27.s[1]", "v27.s[2]", "v27.s[3]",
	"v28.s[0]", "v28.s[1]", "v28.s[2]", "v28.s[3]", "v29.s[0]", "v29.s[1]", "v29.s[2]", "v29.s[3]",
	"v30.s[0]", "v30.s[1]", "v30.s[2]", "v30.s[3]", "v31.s[0]", "v31.s[1]", "v31.s[2]", "v31.s[3]",
	// D vectors
	"v0.d[0]", "v0.d[1]", "v1.d[0]", "v1.d[1]", "v2.d[0]", "v2.d[1]", "v3.d[0]", "v3.d[1]",
	"v4.d[0]", "v4.d[1]", "v5.d[0]", "v5.d[1]", "v6.d[0]", "v6.d[1]", "v7.d[0]", "v7.d[1]",
	"v8.d[0]", "v8.d[1]", "v9.d[0]", "v9.d[1]", "v10.d[0]", "v10.d[1]", "v11.d[0]", "v11.d[1]",
	"v12.d[0]", "v12.d[1]", "v13.d[0]", "v13.d[1]", "v14.d[0]", "v14.d[1]", "v15.d[0]", "v15.d[1]",
	"v16.d[0]", "v16.d[1]", "v17.d[0]", "v17.d[1]", "v18.d[0]", "v18.d[1]", "v19.d[0]", "v19.d[1]",
	"v20.d[0]", "v20.d[1]", "v21.d[0]", "v21.d[1]", "v22.d[0]", "v22.d[1]", "v23.d[0]", "v23.d[1]",
	"v24.d[0]", "v24.d[1]", "v25.d[0]", "v25.d[1]", "v26.d[0]", "v26.d[1]", "v27.d[0]", "v27.d[1]",
	"v28.d[0]", "v28.d[1]", "v29.d[0]", "v29.d[1]", "v30.d[0]", "v30.d[1]", "v31.d[0]", "v31.d[1]",
	// SVE
	"z0",  "z1",  "z2",  "z3",  "z4",  "z5",  "z6",  "z7",
	"z8",  "z9",  "z10", "z11", "z12", "z13", "z14", "z15",
	"z16", "z17", "z18", "z19", "z20", "z21", "z22", "z23",
	"z24", "z25", "z26", "z27", "z28", "z29", "z30", "z31", "z31",
	/* scalable predicate registers */
	"p0",  "p1",  "p2",  "p3",  "p4",  "p5",  "p6",  "p7",
	"p8",  "p9",  "p10", "p11", "p12", "p13", "p14", "p15",
	"p16", "p17", "p18", "p19", "p20", "p21", "p22", "p23",
	"p24", "p25", "p26", "p27", "p28", "p29", "p30", "p31",
	/* prefetch operations (TODO: remove these as registers) */
	"pldl1keep", "pldl1strm", "pldl2keep", "pldl2strm",
	"pldl3keep", "pldl3strm", "#0x6",	  "#0x7",
	"plil1keep", "plil1strm", "plil2keep", "plil2strm",
	"plil3keep", "plil3strm", "#0xe",		"#0xf",
	"pstl1keep", "pstl1strm", "pstl2keep", "pstl2strm",
	"pstl3keep", "pstl3strm", "#0x16", "#0x17",
	"#0x18", "#0x19", "#0x1a", "#0x1b",
	"#0x1c", "#0x1d", "#0x1e", "#0x1f",
	"END"
};

const char *get_register_name(Register r)
{
	if(r>REG_NONE && r<REG_END)
		return RegisterString[r];

	return "";
}

const char *get_register_arrspec(Register reg, const InstructionOperand *operand)
{
	if(operand->arrSpec == ARRSPEC_NONE)
		return "";

	bool is_simd = reg >= REG_V0 && reg <= REG_V31;
	bool is_sve = reg >= REG_Z0 && reg <= REG_Z31;
	bool is_pred = reg >= REG_P0 && reg <= REG_P31;

	if(!is_simd && !is_sve && !is_pred)
		return "";

	/* truncated form */
	if(operand->laneUsed || is_sve || is_pred) {
		switch(operand->arrSpec) {
			case ARRSPEC_FULL: return ".q";
			case ARRSPEC_2DOUBLES: return ".d";
			case ARRSPEC_4SINGLES: return ".s";
			case ARRSPEC_8HALVES: return ".h";
			case ARRSPEC_16BYTES: return ".b";
			case ARRSPEC_1DOUBLE: return ".d";
			case ARRSPEC_2SINGLES: return ".s";
			case ARRSPEC_4HALVES: return ".h";
			case ARRSPEC_8BYTES: return ".b";
			case ARRSPEC_1SINGLE: return ".s";
			case ARRSPEC_2HALVES: return ".h";
			case ARRSPEC_4BYTES: return ".b";
			case ARRSPEC_1HALF: return ".h";
			case ARRSPEC_1BYTE: return ".b";
			default: return "";
		}
	}

	/* non-truncated */
	switch(operand->arrSpec) {
		case ARRSPEC_FULL: return ".1q";
		case ARRSPEC_2DOUBLES: return ".2d";
		case ARRSPEC_4SINGLES: return ".4s";
		case ARRSPEC_8HALVES: return ".8h";
		case ARRSPEC_16BYTES: return ".16b";
		case ARRSPEC_1DOUBLE: return ".1d";
		case ARRSPEC_2SINGLES: return ".2s";
		case ARRSPEC_4HALVES: return ".4h";
		case ARRSPEC_8BYTES: return ".8b";
		case ARRSPEC_1SINGLE: return ".1s";
		case ARRSPEC_2HALVES: return ".2h";
		case ARRSPEC_4BYTES: return ".4b";
		case ARRSPEC_1HALF: return ".1h";
		case ARRSPEC_1BYTE: return ".1b";
		default: return "";
	}
}

int get_register_full(Register reg, const InstructionOperand *operand, char *result)
{
	strcpy(result, get_register_name(reg));
	if(result[0] == '\0')
		return -1;

	strcat(result, get_register_arrspec(reg, operand));

	return 0;
}

unsigned get_register_size(Register r)
{
	//Comparison done in order of likelyhood to occur
	if ((r >= REG_X0 && r <= REG_SP) || (r >= REG_D0 && r <= REG_D31))
		return 8;
	else if ((r >= REG_W0 && r <= REG_WSP) || (r >= REG_S0 && r <= REG_S31))
		return 4;
	else if (r >= REG_B0 && r <= REG_B31)
		return 1;
	else if (r >= REG_H0 && r <= REG_H31)
		return 2;
	else if ((r >= REG_Q0 && r <= REG_Q31) || (r >= REG_V0 && r <= REG_V31))
		return 16;
	return 0;
}

//-----------------------------------------------------------------------------
// decode or decompose
//-----------------------------------------------------------------------------

int decode_spec(context *ctx, Instruction *dec); // decode0.cpp
int decode_scratchpad(context *ctx, Instruction *dec); // decode_scratchpad.cpp

int aarch64_decompose(uint32_t instructionValue, Instruction *instr, uint64_t address)
{
	context ctx;
	memset(&ctx, 0, sizeof(ctx));
	ctx.halted = 1; // enabled disassembly of exception instructions like DCPS1
	ctx.insword = instructionValue;
	ctx.address = address;
	ctx.features0 = 0xFFFFFFFFFFFFFFFF;
	ctx.features1 = 0xFFFFFFFFFFFFFFFF;
	ctx.EDSCR_HDE = 1;

	/* have the spec-generated code populate all the pcode variables */
	int rc = decode_spec(&ctx, instr);
	if(rc != DECODE_STATUS_OK)
		return rc;

	/* if UDF encoding, return undefined */
	if(instr->encoding == ENC_UDF_ONLY_PERM_UNDEF)
		return DECODE_STATUS_UNDEFINED;

	/* convert the pcode variables to list of operands, etc. */
	return decode_scratchpad(&ctx, instr);
}

//-----------------------------------------------------------------------------
// disassemble helpers
//-----------------------------------------------------------------------------

static const char *ConditionString[] = {
	"eq", "ne", "cs", "cc",
	"mi", "pl", "vs", "vc",
	"hi", "ls", "ge", "lt",
	"gt", "le", "al", "nv"
};

const char *get_condition(Condition cond)
{
	if (cond < 0 || cond >= END_CONDITION)
		return NULL;

	return ConditionString[cond];
}

static const char *ShiftString[] = {
	"NONE", "lsl", "lsr", "asr",
	"ror",  "uxtw", "sxtw", "sxtx",
	"uxtx", "sxtb", "sxth", "uxth",
	"uxtb", "msl"
};

const char *get_shift(ShiftType shift)
{
	if (shift <= ShiftType_NONE || shift >= ShiftType_END)
		return NULL;

	return ShiftString[shift];
}

static inline uint32_t get_shifted_register(
	const InstructionOperand *operand,
	uint32_t registerNumber,
	char *outBuffer,
	uint32_t outBufferSize)
{
	char immBuff[32] = {0};
	char shiftBuff[64] = {0};

	char reg[16];
	if(get_register_full(operand->reg[registerNumber], operand, reg))
		return FAILED_TO_DISASSEMBLE_REGISTER;

	if (operand->shiftType != ShiftType_NONE)
	{
		if (operand->shiftValueUsed != 0)
		{
			if (snprintf(immBuff, sizeof(immBuff), " #%#x", operand->shiftValue) >= sizeof(immBuff))
			{
				return FAILED_TO_DISASSEMBLE_REGISTER;
			}
		}
		const char *shiftStr = get_shift(operand->shiftType);
		if (shiftStr == NULL)
			return FAILED_TO_DISASSEMBLE_OPERAND;
		snprintf(
				shiftBuff,
				sizeof(shiftBuff),
				", %s%s",
				shiftStr,
				immBuff);
	}
	if (snprintf(outBuffer, outBufferSize, "%s%s", reg, shiftBuff) < 0)
		return FAILED_TO_DISASSEMBLE_REGISTER;
	return DISASM_SUCCESS;
}

uint32_t get_memory_operand(
	const InstructionOperand *operand,
	char *outBuffer,
	uint32_t outBufferSize)
{
	char immBuff[64]= {0};
	char extendBuff[48] = {0};
	char paramBuff[32] = {0};

	char reg0[16]={'\0'}, reg1[16]={'\0'};
	if(get_register_full(operand->reg[0], operand, reg0))
		return FAILED_TO_DISASSEMBLE_REGISTER;

	const char *sign = "";
	int64_t imm = operand->immediate;
	if (operand->signedImm && (int64_t)imm < 0)
	{
		sign = "-";
		imm = -imm;
	}

	switch (operand->operandClass)
	{
		case MEM_REG:
			if (snprintf(outBuffer, outBufferSize, "[%s]", reg0) >= outBufferSize)
				return FAILED_TO_DISASSEMBLE_OPERAND;
			break;

		case MEM_PRE_IDX:
			if (snprintf(outBuffer, outBufferSize, "[%s, #%s%#" PRIx64 "]!", reg0, sign, (uint64_t)imm) >= outBufferSize)
				return FAILED_TO_DISASSEMBLE_OPERAND;
			break;

		case MEM_POST_IDX: // [<reg>], <reg|imm>
			if (operand->reg[1] != REG_NONE) {
				if(get_register_full((Register)operand->reg[1], operand, reg1))
					return FAILED_TO_DISASSEMBLE_REGISTER;

				snprintf(paramBuff, sizeof(paramBuff), ", %s", reg1);
			}
			else if (snprintf(paramBuff, sizeof(paramBuff), ", #%s%#" PRIx64, sign, (uint64_t)imm) >= sizeof(paramBuff))
				return FAILED_TO_DISASSEMBLE_OPERAND;

			if (snprintf(outBuffer, outBufferSize, "[%s]%s", reg0, paramBuff) >= outBufferSize)
				return FAILED_TO_DISASSEMBLE_OPERAND;

			break;

		case MEM_OFFSET: // [<reg> optional(imm)]
			if (operand->immediate != 0) {
				const char *mul_vl = operand->mul_vl ? ", mul vl" : "";
				if(snprintf(immBuff, sizeof(immBuff), ", #%s%#" PRIx64 "%s", sign, (uint64_t)imm, mul_vl) >= sizeof(immBuff)) {
					return FAILED_TO_DISASSEMBLE_OPERAND;
				}
			}

			if (snprintf(outBuffer, outBufferSize, "[%s%s]", reg0, immBuff) >= outBufferSize)
				return FAILED_TO_DISASSEMBLE_OPERAND;
			break;

		case MEM_EXTENDED:
			if(get_register_full(operand->reg[1], operand, reg1))
				return FAILED_TO_DISASSEMBLE_REGISTER;

			if (reg0[0] == '\0' || reg1[0] == '\0') {
				return FAILED_TO_DISASSEMBLE_OPERAND;
			}

			// immBuff, like "#0x0"
			if (operand->shiftValueUsed)
				if(snprintf(immBuff, sizeof(immBuff), " #%#x", operand->shiftValue) >= sizeof(immBuff))
					return FAILED_TO_DISASSEMBLE_OPERAND;

			// extendBuff, like "lsl #0x0"
			if (operand->shiftType != ShiftType_NONE)
			{
				if (snprintf(extendBuff, sizeof(extendBuff), ", %s%s",
							ShiftString[operand->shiftType], immBuff) >= sizeof(extendBuff))
				{
					return FAILED_TO_DISASSEMBLE_OPERAND;
				}
			}

			// together, like "[x24, x30, lsl #0x0]"
			if (snprintf(outBuffer, outBufferSize, "[%s, %s%s]", reg0, reg1, extendBuff) >= outBufferSize)
				return FAILED_TO_DISASSEMBLE_OPERAND;

			break;
		default:
			return NOT_MEMORY_OPERAND;
	}
	return DISASM_SUCCESS;
}

uint32_t get_register(const InstructionOperand *operand, uint32_t registerNumber, char *outBuffer, uint32_t outBufferSize)
{

	/* 1) handle system registers */
	if(operand->operandClass == SYS_REG)
	{
		if (snprintf(outBuffer, outBufferSize, "%s",
			get_system_register_name(operand->sysreg)) >= outBufferSize)
			return FAILED_TO_DISASSEMBLE_REGISTER;
		return 0;
	}

	if(operand->operandClass != REG && operand->operandClass != MULTI_REG)
		return OPERAND_IS_NOT_REGISTER;

	/* 2) handle shifted registers */
	if (operand->shiftType != ShiftType_NONE)
	{
		return get_shifted_register(operand, registerNumber, outBuffer, outBufferSize);
	}

	char reg_buf[16];
	if(get_register_full(operand->reg[registerNumber], operand, reg_buf))
		return FAILED_TO_DISASSEMBLE_REGISTER;

	/* 3) handle predicate registers */
	if(operand->operandClass == REG && operand->pred_qual && operand->reg[0] >= REG_P0 && operand->reg[0] <= REG_P31)
	{
		if(snprintf(outBuffer, outBufferSize, "%s/%c", reg_buf, operand->pred_qual) >= outBufferSize)
			return FAILED_TO_DISASSEMBLE_REGISTER;
		return 0;
	}

	/* 4) handle other registers */
	char scale[32] = {0};
	if (operand->scale != 0)
		snprintf(scale, sizeof(scale), "[%u]", 0x7fffffff & operand->scale);

	char index[32] = {0};
	if(operand->operandClass == REG && operand->laneUsed)
		snprintf(index, sizeof(index), "[%u]", operand->lane);

	if(snprintf(outBuffer, outBufferSize, "%s%s%s", reg_buf, scale, index) >= outBufferSize)
		return FAILED_TO_DISASSEMBLE_REGISTER;

	return 0;
}

uint32_t get_multireg_operand(const InstructionOperand *operand, char *result, uint32_t result_sz)
{
	char lane_str[32] = {0};
	char reg_str[4][32];
	uint32_t elem_n;
	int rc;
	memset(&reg_str, 0, sizeof(reg_str));

	for (elem_n = 0; elem_n < 4 && operand->reg[elem_n] != REG_NONE; elem_n++)
		if (get_register(operand, elem_n, reg_str[elem_n], 32) != 0)
			return FAILED_TO_DISASSEMBLE_OPERAND;

	if(operand->laneUsed)
		snprintf(lane_str, sizeof(lane_str), "[%d]", operand->lane);

	switch (elem_n)
	{
		case 1:
			rc = snprintf(result, result_sz, "{%s}%s",
				reg_str[0], lane_str);
			break;
		case 2:
			rc = snprintf(result, result_sz, "{%s, %s}%s",
				reg_str[0], reg_str[1], lane_str);
			break;
		case 3:
			rc = snprintf(result, result_sz, "{%s, %s, %s}%s",
				reg_str[0], reg_str[1], reg_str[2], lane_str);
			break;
		case 4:
			rc = snprintf(result, result_sz, "{%s, %s, %s, %s}%s",
				reg_str[0], reg_str[1], reg_str[2], reg_str[3], lane_str);
			break;
		default:
			return FAILED_TO_DISASSEMBLE_OPERAND;
	}

	return rc < 0 ? FAILED_TO_DISASSEMBLE_OPERAND : DISASM_SUCCESS;
}

uint32_t get_shifted_immediate(const InstructionOperand *instructionOperand, char *outBuffer, uint32_t outBufferSize, uint32_t type)
{
	char shiftBuff[48] = {0};
	char immBuff[32] = {0};
	const char *sign = "";
	if (instructionOperand == NULL)
		return FAILED_TO_DISASSEMBLE_OPERAND;

	uint64_t imm = instructionOperand->immediate;
	if (instructionOperand->signedImm == 1 && ((int64_t)imm) < 0)
	{
		sign = "-";
		imm = -(int64_t)imm;
	}
	if (instructionOperand->shiftType != ShiftType_NONE)
	{
		if (instructionOperand->shiftValueUsed != 0)
		{
			if (snprintf(immBuff, sizeof(immBuff), " #%#x", instructionOperand->shiftValue) >= sizeof(immBuff))
			{
				return FAILED_TO_DISASSEMBLE_REGISTER;
			}
		}
		const char *shiftStr = get_shift(instructionOperand->shiftType);
		if (shiftStr == NULL)
			return FAILED_TO_DISASSEMBLE_OPERAND;
		snprintf(
				shiftBuff,
				sizeof(shiftBuff),
				", %s%s",
				shiftStr,
				immBuff);
	}
	if (type == FIMM32)
	{
		float f = *(const float*)&instructionOperand->immediate;
		if (snprintf(outBuffer, outBufferSize, "#%.08f%s", f, shiftBuff) >= outBufferSize)
			return FAILED_TO_DISASSEMBLE_OPERAND;
	}
	else if (type == IMM32)
	{
		if (snprintf(outBuffer, outBufferSize, "#%s%#x%s", sign, (uint32_t)imm, shiftBuff) >= outBufferSize)
			return FAILED_TO_DISASSEMBLE_OPERAND;
	}
	else if (type == LABEL)
	{
		if (snprintf(outBuffer, outBufferSize, "0x%" PRIx64, (uint64_t)imm) >= outBufferSize)
			return FAILED_TO_DISASSEMBLE_OPERAND;
	}
	else if (type == STR_IMM)
	{
		if (snprintf(outBuffer, outBufferSize, "%s #0x%" PRIx64, instructionOperand->name, (uint64_t)imm) >= outBufferSize)
			return FAILED_TO_DISASSEMBLE_OPERAND;
	}
	else
	{
		if (snprintf(outBuffer, outBufferSize, "#%s%#" PRIx64 "%s",
					sign,
					imm,
					shiftBuff) >= outBufferSize)
			return FAILED_TO_DISASSEMBLE_OPERAND;
	}
	return DISASM_SUCCESS;
}

uint32_t get_implementation_specific(const InstructionOperand *operand, char *outBuffer, uint32_t outBufferSize)
{
	return snprintf(outBuffer,
			outBufferSize,
			"s%d_%d_c%d_c%d_%d",
			operand->implspec[0],
			operand->implspec[1],
			operand->implspec[2],
			operand->implspec[3],
			operand->implspec[4]) >= outBufferSize;
}

const char *get_operation(const Instruction *inst)
{
	return operation_to_str(inst->operation);
}

//-----------------------------------------------------------------------------
// disassemble (decoded Instruction -> string)
//-----------------------------------------------------------------------------

int aarch64_disassemble(Instruction *instruction, char *buf, size_t buf_sz)
{
	char operandStrings[MAX_OPERANDS][130];
	char tmpOperandString[128];
	const char *operand = tmpOperandString;
	if (instruction == NULL || buf_sz == 0 || buf == NULL)
		return INVALID_ARGUMENTS;

	memset(operandStrings, 0, sizeof(operandStrings));
	const char *operation = get_operation(instruction);
	if (operation == NULL)
		return FAILED_TO_DISASSEMBLE_OPERATION;

	for(int i=0; i<MAX_OPERANDS; i++)
		memset(&(operandStrings[i][0]), 0, 128);

	for(int i=0; i<MAX_OPERANDS && instruction->operands[i].operandClass != NONE; i++)
	{
		switch (instruction->operands[i].operandClass)
		{
			case FIMM32:
			case IMM32:
			case IMM64:
			case LABEL:
			case STR_IMM:
				if (get_shifted_immediate(
							&instruction->operands[i],
							tmpOperandString,
							sizeof(tmpOperandString),
							instruction->operands[i].operandClass) != DISASM_SUCCESS)
					return FAILED_TO_DISASSEMBLE_OPERAND;
				operand = tmpOperandString;
				break;
			case REG:
				if (get_register(
						&instruction->operands[i],
						0,
						tmpOperandString,
						sizeof(tmpOperandString)) != DISASM_SUCCESS)
					return FAILED_TO_DISASSEMBLE_OPERAND;
				operand = tmpOperandString;
				break;
			case SYS_REG:
				operand = get_system_register_name(instruction->operands[i].sysreg);
				if (operand == NULL)
				{
					return FAILED_TO_DISASSEMBLE_OPERAND;
				}
				break;
			case MULTI_REG:
				if (get_multireg_operand(
							&instruction->operands[i],
							tmpOperandString,
							sizeof(tmpOperandString)) != DISASM_SUCCESS)
				{
					return FAILED_TO_DISASSEMBLE_OPERAND;
				}
				operand = tmpOperandString;
				break;
			case IMPLEMENTATION_SPECIFIC:
				if (get_implementation_specific(
						&instruction->operands[i],
						tmpOperandString,
						sizeof(tmpOperandString)) != DISASM_SUCCESS)
				{
					return FAILED_TO_DISASSEMBLE_OPERAND;
				}
				operand = tmpOperandString;
				break;
			case MEM_REG:
			case MEM_OFFSET:
			case MEM_EXTENDED:
			case MEM_PRE_IDX:
			case MEM_POST_IDX:
				if (get_memory_operand(&instruction->operands[i],
							tmpOperandString,
							sizeof(tmpOperandString)) != DISASM_SUCCESS)
					return FAILED_TO_DISASSEMBLE_OPERAND;
				operand = tmpOperandString;
				break;
			case CONDITION:
				if (snprintf(tmpOperandString, sizeof(tmpOperandString), "%s",
							get_condition((Condition)instruction->operands[i].cond)) >= sizeof(tmpOperandString))
					return FAILED_TO_DISASSEMBLE_OPERAND;
				operand = tmpOperandString;
				break;
			case NAME:
				operand = instruction->operands[i].name;
				break;
			case NONE:
				break;
		}
		snprintf(operandStrings[i], sizeof(operandStrings[i]), i==0?"\t%s":", %s", operand);
	}
	memset(buf, 0, buf_sz);
	if (snprintf(buf, buf_sz, "%s%s%s%s%s%s",
				get_operation(instruction),
				operandStrings[0],
				operandStrings[1],
				operandStrings[2],
				operandStrings[3],
				operandStrings[4]) >= buf_sz)
		return OUTPUT_BUFFER_TOO_SMALL;
	return DISASM_SUCCESS;
}

void print_instruction(Instruction *instr)
{
	//printf("print_instruction (TODO)\n");
}

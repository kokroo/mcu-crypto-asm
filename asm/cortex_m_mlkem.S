// Machine-generated and cleaned from PQM4 (crypto_kem/ml-kem-768/m4fspeed/)
// Integrating the improved Plantard arithmetic into Kyber/ML-KEM (FIPS 203).
// Reference: Junhao Huang, BNU-HKBU UIC (https://eprint.iacr.org/2022/956.pdf)
// License: CC0 / Apache-2.0

.syntax unified
.thumb
.text
/******************************************************************************
 * Integrating the improved Plantard arithmetic into Kyber.
 *
 * Efficient Plantard arithmetic enables a faster Kyber implementation with the
 * same stack usage.
 *
 * See the paper at https://eprint.iacr.org/2022/956.pdf for more details.
 *
 * @author   Junhao Huang, BNU-HKBU United International College, Zhuhai, China
 *           jhhuang_nuaa@126.com
 *
 * @date     September 2022
 ******************************************************************************/
#ifndef MACROS_I
#define MACROS_I

.macro load a, a0, a1, a2, a3, mem0, mem1, mem2, mem3
  ldr.w \a0, [\a, \mem0]
  ldr.w \a1, [\a, \mem1]
  ldr.w \a2, [\a, \mem2]
  ldr.w \a3, [\a, \mem3]
.endm

.macro store a, a0, a1, a2, a3, mem0, mem1, mem2, mem3
  str.w \a0, [\a, \mem0]
  str.w \a1, [\a, \mem1]
  str.w \a2, [\a, \mem2]
  str.w \a3, [\a, \mem3]
.endm

.macro doubleplant a, tmp, q, qa, plantconst
	smulwb \tmp, \plantconst, \a
	smulwt \a, \plantconst, \a
	smlabt \tmp, \tmp, \q, \qa
	smlabt \a, \a, \q, \qa
	pkhtb \a, \a, \tmp, asr#16
.endm

.macro doublebarrett a, tmp, tmp2, q, barrettconst
  smulbb \tmp, \a, \barrettconst
  smultb \tmp2, \a, \barrettconst
  asr \tmp, \tmp, #26
  asr \tmp2, \tmp2, #26
  smulbb \tmp, \tmp, \q
  smulbb \tmp2, \tmp2, \q
  pkhbt \tmp, \tmp, \tmp2, lsl#16
  usub16 \a, \a, \tmp
.endm

// q locate in the top half of the register
.macro plant_red q, qa, qinv, tmp
	mul \tmp, \tmp, \qinv     
	//tmp*qinv mod 2^2n/ 2^n; in high half
	smlatt \tmp, \tmp, \q, \qa
	// result in high half
.endm



#endif /* MACROS_I */

/******************************************************************************
* Integrating the improved Plantard arithmetic into Kyber.
*
* Efficient Plantard arithmetic enables a faster Kyber implementation with the 
* same stack usage.
*
* See the paper at https://eprint.iacr.org/2022/956.pdf for more details.
*
* @author   Junhao Huang, BNU-HKBU United International College, Zhuhai, China
*           jhhuang_nuaa@126.com
*
* @date     September 2022
******************************************************************************/


.syntax unified
.cpu cortex-m4
.thumb

.macro mul_twiddle_plant a, twiddle, tmp, q, qa
	smulwb \tmp, \twiddle, \a
	smulwt \a,   \twiddle, \a
	smlabt \tmp, \tmp, \q, \qa
	smlabt \a, \a, \q, \qa
	pkhtb \a, \a, \tmp, asr#16
.endm

.macro doublebutterfly_plant a0, a1, twiddle, tmp, q, qa
	smulwb \tmp, \twiddle, \a1
	smulwt \a1, \twiddle, \a1
	smlabt \tmp, \tmp, \q, \qa
	smlabt \a1, \a1, \q, \qa
	pkhtb \tmp, \a1, \tmp, asr#16
	usub16 \a1, \a0, \tmp
	uadd16 \a0, \a0, \tmp
.endm

.macro two_doublebutterfly_plant a0, a1, a2, a3, twiddle0, twiddle1, tmp, q, qa
	doublebutterfly_plant \a0, \a1, \twiddle0, \tmp, \q, \qa
	doublebutterfly_plant \a2, \a3, \twiddle1, \tmp, \q, \qa
.endm

.macro _3_layer_double_CT_16_plant c0, c1, c2, c3, c4, c5, c6, c7, twiddle1, twiddle2, twiddle_ptr, q, qa, tmp
	// layer 3
	ldr.w \twiddle1, [\twiddle_ptr], #4
	two_doublebutterfly_plant \c0, \c4, \c1, \c5, \twiddle1, \twiddle1, \tmp, \q, \qa
	two_doublebutterfly_plant \c2, \c6, \c3, \c7, \twiddle1, \twiddle1, \tmp, \q, \qa

	// layer 2
	ldrd \twiddle1, \twiddle2, [\twiddle_ptr], #8
	two_doublebutterfly_plant \c0, \c2, \c1, \c3, \twiddle1, \twiddle1, \tmp, \q, \qa

	two_doublebutterfly_plant \c4, \c6, \c5, \c7, \twiddle2, \twiddle2, \tmp, \q, \qa

	// layer 1
	ldrd \twiddle1, \twiddle2, [\twiddle_ptr], #8
	two_doublebutterfly_plant \c0, \c1, \c2, \c3, \twiddle1, \twiddle2, \tmp, \q, \qa

	ldrd \twiddle1, \twiddle2, [\twiddle_ptr], #8
	two_doublebutterfly_plant \c4, \c5, \c6, \c7, \twiddle1, \twiddle2, \tmp, \q, \qa
.endm

.macro _3_layer_double_CT_16_plant_fp c0, c1, c2, c3, c4, c5, c6, c7, xi0, xi1, xi2, xi3, xi4, xi5, xi6, twiddle1, twiddle2, q, qa, tmp
	// layer 3
	vmov \twiddle1, \xi0
	two_doublebutterfly_plant \c0, \c4, \c1, \c5, \twiddle1, \twiddle1, \tmp, \q, \qa
	two_doublebutterfly_plant \c2, \c6, \c3, \c7, \twiddle1, \twiddle1, \tmp, \q, \qa

	// layer 2
	vmov \twiddle1, \xi1
	vmov \twiddle2, \xi2
	two_doublebutterfly_plant \c0, \c2, \c1, \c3, \twiddle1, \twiddle1, \tmp, \q, \qa

	two_doublebutterfly_plant \c4, \c6, \c5, \c7, \twiddle2, \twiddle2, \tmp, \q, \qa

	// layer 1
	vmov \twiddle1, \xi3
	vmov \twiddle2, \xi4
	two_doublebutterfly_plant \c0, \c1, \c2, \c3, \twiddle1, \twiddle2, \tmp, \q, \qa

	vmov \twiddle1, \xi5
	vmov \twiddle2, \xi6
	two_doublebutterfly_plant \c4, \c5, \c6, \c7, \twiddle1, \twiddle2, \tmp, \q, \qa
.endm

.thumb_func
.global ntt_fast
.type ntt_fast, %function
.align 2
ntt_fast:
	push {r4-r11, r14}
	vpush {s16-s25}
	poly         .req r0
	twiddle_ptr  .req r1
	poly0        .req r2
	poly1        .req r3
	poly2        .req r4
	poly3        .req r5
	poly4        .req r6
	poly5        .req r7
	poly6        .req r8
	poly7        .req r9
	twiddle1     .req r10
	twiddle2     .req r11
	###  qinv        .req r11 ### q^-1 mod 2^2n; n=16
	q           .req r12 
	### at the top of r12
	qa          .req r0
	### qa=2^a q;a=3; at the bottom of r12
	tmp         .req r14

	// movw qa, #26632
	// Why movt? Because we initially placed qa at the bottom of the same register as q;
	movt q, #3329

	### LAYER 7+6+5+4
	.equ distance, 256
	.equ offset, 32
	.equ strincr, 4
	// pre-load 15 twiddle factors to 15 FPU registers
	// s0-s7 used to temporary store 16 16-bit polys.
	vldm twiddle_ptr!, {s8-s22}
 
	add tmp, poly, #strincr*8
	// s23: poly addr
	// s24: tmp  
	vmov s24, tmp  
	1:
		// load a1, a3, ..., a15
		vmov s23, poly
		load poly, poly0, poly1, poly2, poly3, #offset, #distance/4+offset, #2*distance/4+offset, #3*distance/4+offset
		load poly, poly4, poly5, poly6, poly7, #distance+offset, #5*distance/4+offset, #6*distance/4+offset, #7*distance/4+offset
		
		movw qa, #26632

		// 8-NTT on a1, a3, ..., a15
		_3_layer_double_CT_16_plant_fp poly0, poly1, poly2, poly3, poly4, poly5, poly6, poly7, s8, s9, s10, s11, s12, s13, s14, twiddle1, twiddle2, q, qa, tmp

		// s15, s16, s17, s18, s19, s20, s21, s22 left
		// multiply coeffs by layer 8 twiddles for later use
		vmov twiddle1, s15 
		vmov twiddle2, s16 
		mul_twiddle_plant poly0, twiddle1, tmp, q, qa
		mul_twiddle_plant poly1, twiddle2, tmp, q, qa

		vmov twiddle1, s17 
		vmov twiddle2, s18 
		mul_twiddle_plant poly2, twiddle1, tmp, q, qa
		mul_twiddle_plant poly3, twiddle2, tmp, q, qa

		vmov twiddle1, s19 
		vmov twiddle2, s20 
		mul_twiddle_plant poly4, twiddle1, tmp, q, qa
		mul_twiddle_plant poly5, twiddle2, tmp, q, qa

		vmov twiddle1, s21 
		vmov twiddle2, s22 
		mul_twiddle_plant poly6, twiddle1, tmp, q, qa
		mul_twiddle_plant poly7, twiddle2, tmp, q, qa

		vmov s0, poly0 // a1
		vmov s1, poly1 // a3
		vmov s2, poly2 // a5
		vmov s3, poly3 // a7
		vmov s4, poly4 // a9
		vmov s5, poly5 // a11
		vmov s6, poly6 // a13
		vmov s7, poly7 // a15

		vmov poly, s23
	
		// load a0, a2, ..., a14
		load poly, poly0, poly1, poly2, poly3, #0, #distance/4, #2*distance/4, #3*distance/4
		load poly, poly4, poly5, poly6, poly7, #distance, #5*distance/4, #6*distance/4, #7*distance/4
		
		movw qa, #26632
		// 8-NTT on a0, a2, ..., a14
		_3_layer_double_CT_16_plant_fp poly0, poly1, poly2, poly3, poly4, poly5, poly6, poly7, s8, s9, s10, s11, s12, s13, s14, twiddle1, twiddle2, q, qa, tmp

		
		// layer 4 - 1
		// addsub: (a2, a6, a10, a14), (a3, a7, a11, a15)
		vmov poly, s23
		vmov twiddle1, s1 // load a3
		uadd16 tmp, poly1, twiddle1
		usub16 poly1, poly1, twiddle1
		str.w tmp, [poly, #1*distance/4]
		str.w poly1, [poly, #1*distance/4+offset]

		vmov twiddle1, s3 // load a7
		uadd16 tmp, poly3, twiddle1
		usub16 poly3, poly3, twiddle1
		str.w tmp, [poly, #3*distance/4]
		str.w poly3, [poly, #3*distance/4+offset]
		
		vmov twiddle1, s5 // load a11
		uadd16 tmp, poly5, twiddle1
		usub16 poly5, poly5, twiddle1
		str.w tmp, [poly, #5*distance/4]
		str.w poly5, [poly, #5*distance/4+offset]
		
		vmov twiddle1, s7 // load a15
		uadd16 tmp, poly7, twiddle1
		usub16 poly7, poly7, twiddle1
		str.w tmp, [poly, #7*distance/4]
		str.w poly7, [poly, #7*distance/4+offset]
		
		// layer 4 - 2    
		// addsub: (a0, a4, a8, a12), (a1, a5, a9, a13)
		vmov poly3, s2 // load a5
		uadd16 tmp, poly2, poly3
		usub16 twiddle1, poly2, poly3
		str.w tmp, [poly, #2*distance/4]
		str.w twiddle1, [poly, #2*distance/4+offset]

		vmov poly5, s4 // load a9
		uadd16 tmp, poly4, poly5
		usub16 twiddle1, poly4, poly5
		str.w tmp, [poly, #4*distance/4]
		str.w twiddle1, [poly, #4*distance/4+offset]

		vmov poly7, s6 // load a13
		uadd16 tmp, poly6, poly7
		usub16 twiddle1, poly6, poly7
		str.w tmp, [poly, #6*distance/4]
		str.w twiddle1, [poly, #6*distance/4+offset]
		
		vmov poly1, s0 // load a1
		uadd16 tmp, poly0, poly1
		usub16 twiddle1, poly0, poly1
		str.w twiddle1, [poly, #offset]
		str.w tmp, [poly], #4

	vmov tmp, s24
	cmp.w poly, tmp
	bne.w 1b

	sub.w poly, poly, #32

	### LAYER 3+2+1

	.equ distance, distance/16
	.equ strincr, 32

	add.w tmp, poly, #strincr*16
	vmov s13, tmp
	2:
		vmov s23, poly
		load poly, poly0, poly1, poly2, poly3, #0, #distance/4, #2*distance/4, #3*distance/4
		load poly, poly4, poly5, poly6, poly7, #distance, #5*distance/4, #6*distance/4, #7*distance/4
		
		movw qa, #26632
		_3_layer_double_CT_16_plant poly0, poly1, poly2, poly3, poly4, poly5, poly6, poly7, twiddle1, twiddle2, twiddle_ptr, q, qa, tmp
		
		vmov poly, s23
		store poly, poly4, poly5, poly6, poly7, #distance, #5*distance/4, #6*distance/4, #7*distance/4
		str.w poly1, [poly, #distance/4]
		str.w poly2, [poly, #2*distance/4]
		str.w poly3, [poly, #3*distance/4]
		str.w poly0, [poly], #strincr

	vmov tmp, s13
	cmp.w poly, tmp
	bne.w 2b
	vpop {s16-s25}
	.unreq poly
	.unreq twiddle_ptr
	.unreq poly0
	.unreq poly1
	.unreq poly2
	.unreq poly3
	.unreq poly4
	.unreq poly5
	.unreq poly6
	.unreq poly7
	.unreq twiddle1
	.unreq twiddle2
	.unreq q
	.unreq qa
	.unreq tmp
	pop {r4-r11, pc}

/******************************************************************************
* Integrating the improved Plantard arithmetic into Kyber.
*
* Efficient Plantard arithmetic enables a faster Kyber implementation with the 
* same stack usage.
*
* See the paper at https://eprint.iacr.org/2022/956.pdf for more details.
*
* @author   Junhao Huang, BNU-HKBU United International College, Zhuhai, China
*           jhhuang_nuaa@126.com
*
* @date     September 2022
******************************************************************************/


.syntax unified
.cpu cortex-m4
.thumb







.macro fullplant a0, a1, a2, a3, a4, a5, a6, a7, tmp, q, qa, plantconst
	movw \plantconst, #44984
	movt \plantconst, #19
	doubleplant \a0, \tmp, \q, \qa, \plantconst
	doubleplant \a1, \tmp, \q, \qa, \plantconst
	doubleplant \a2, \tmp, \q, \qa, \plantconst
	doubleplant \a3, \tmp, \q, \qa, \plantconst
	doubleplant \a4, \tmp, \q, \qa, \plantconst
	doubleplant \a5, \tmp, \q, \qa, \plantconst
	doubleplant \a6, \tmp, \q, \qa, \plantconst
	doubleplant \a7, \tmp, \q, \qa, \plantconst
.endm

.macro halfplant a0, a1, a2, a3, tmp, q, qa, plantconst
	movw \plantconst, #44984
	movt \plantconst, #19
	doubleplant \a0, \tmp, \q, \qa, \plantconst
	doubleplant \a1, \tmp, \q, \qa, \plantconst
	doubleplant \a2, \tmp, \q, \qa, \plantconst
	doubleplant \a3, \tmp, \q, \qa, \plantconst
.endm


// input: 0.5/1q
.macro _3_layer_double_inv_CT_16_plant_light c0, c1, c2, c3, c4, c5, c6, c7, xi2, xi4, xi5, xi6, twiddle1, tmp2, q, qa, tmp

	// layer 1  
	sadd16 \tmp, \c0, \c1 // c0, c1
	ssub16 \c1, \c0, \c1
	sadd16 \tmp2, \c2, \c3 // c2, c3
	ssub16 \c3, \c2, \c3
	// tmp, c1, tmp2, c3: 1q maximum
	sadd16 \c0, \c4, \c5 // c4, c5
	ssub16 \c5, \c4, \c5
	sadd16 \c2, \c6, \c7 // c6, c7
	ssub16 \c7, \c6, \c7
	// c4, c6 are free at this point
	// c0,c5,c2,c7 1q maximum

	// layer 2
	sadd16 \c6, \tmp, \tmp2 // c0, c2
	ssub16 \tmp2, \tmp, \tmp2
	sadd16 \c4, \c0, \c2 // c4, c6
	ssub16 \c2, \c0, \c2
	// c6, tmp2, c4, c2: 2q maximum

	vmov \twiddle1, \xi2
	doublebutterfly_plant \c1, \c3, \twiddle1, \tmp, \q, \qa
	doublebutterfly_plant \c5, \c7, \twiddle1, \tmp, \q, \qa 
	// c1, c3, c7, c5: 1.5q maximum;

	// tmp and c0 are free at this point
	// layer 3
	sadd16 \c0, \c6, \c4 // c0, c4
	ssub16 \c4, \c6, \c4
	// c0, c4: 4q
	// c6 are free at this point
	vmov \twiddle1, \xi4
	doublebutterfly_plant \c1, \c5, \twiddle1, \tmp, \q, \qa
	// c1, c5: 2q maximum

	vmov \twiddle1, \xi5
	// this block is one doublebutterfly
	smulwb \tmp, \twiddle1, \c2  // c2, c6
	smulwt \c2,  \twiddle1, \c2
	smlabt \tmp, \tmp, \q, \qa
	smlabt \c2, \c2, \q, \qa
	pkhtb \tmp, \c2, \tmp, asr#16
	ssub16 \c6, \tmp2, \tmp 
	sadd16 \c2, \tmp2, \tmp
	//c6, c2: 4.5q
	vmov \twiddle1, \xi6
	doublebutterfly_plant \c3, \c7, \twiddle1, \tmp, \q, \qa
	//c3, c7: 2.5q maximum
.endm
.macro _3_layer_double_inv_CT_16_plant c0, c1, c2, c3, c4, c5, c6, c7, twiddle1, twiddle2, twiddle_ptr, q, qa, tmp
	// layer 3
	ldr.w \twiddle1, [\twiddle_ptr], #4
	two_doublebutterfly_plant \c0, \c1, \c2, \c3, \twiddle1, \twiddle1, \tmp, \q, \qa
	two_doublebutterfly_plant \c4, \c5, \c6, \c7, \twiddle1, \twiddle1, \tmp, \q, \qa

	// layer 2
	ldrd \twiddle1, \twiddle2, [\twiddle_ptr], #8
	two_doublebutterfly_plant \c0, \c2, \c1, \c3, \twiddle1, \twiddle2, \tmp, \q, \qa

	two_doublebutterfly_plant \c4, \c6, \c5, \c7, \twiddle1, \twiddle2, \tmp, \q, \qa

	// layer 1
	ldrd \twiddle1, \twiddle2, [\twiddle_ptr], #8
	two_doublebutterfly_plant \c0, \c4, \c1, \c5, \twiddle1, \twiddle2, \tmp, \q, \qa

	ldrd \twiddle1, \twiddle2, [\twiddle_ptr], #8
	two_doublebutterfly_plant \c2, \c6, \c3, \c7, \twiddle1, \twiddle2, \tmp, \q, \qa
.endm

.macro _3_layer_double_inv_twist_16_plant c0, c1, c2, c3, c4, c5, c6, c7, twiddle1, twiddle2, twiddle_ptr, q, qa, tmp
	ldrd \twiddle1, \twiddle2, [\twiddle_ptr], #8
	mul_twiddle_plant \c0, \twiddle1, \tmp, \q, \qa
	mul_twiddle_plant \c1, \twiddle2, \tmp, \q, \qa
	ldrd \twiddle1, \twiddle2, [\twiddle_ptr], #8
	mul_twiddle_plant \c2, \twiddle1, \tmp, \q, \qa
	mul_twiddle_plant \c3, \twiddle2, \tmp, \q, \qa
	ldrd \twiddle1, \twiddle2, [\twiddle_ptr], #8
	mul_twiddle_plant \c4, \twiddle1, \tmp, \q, \qa
	mul_twiddle_plant \c5, \twiddle2, \tmp, \q, \qa
	ldrd \twiddle1, \twiddle2, [\twiddle_ptr], #8
	mul_twiddle_plant \c6, \twiddle1, \tmp, \q, \qa
	mul_twiddle_plant \c7, \twiddle2, \tmp, \q, \qa
.endm
# input coefficients < 0.5q
.thumb_func
.global invntt_fast
.type invntt_fast, %function
.align 2
invntt_fast:
	push {r4-r11, r14}
	vpush {s16-s23}
	poly         .req r0
	twiddle_ptr  .req r1
	poly0        .req r2
	poly1        .req r3
	poly2        .req r4
	poly3        .req r5
	poly4        .req r6
	poly5        .req r7
	poly6        .req r8
	poly7        .req r9
	twiddle1     .req r10
	twiddle2     .req r11
	q            .req r12 
	// at the top of r12
	qa           .req r0
	// qa=2^a q;a=3; at the bottom of r12
	tmp          .req r14

	movt q, #3329

	### LAYER 7+6+5+4
	.equ distance, 16
	.equ offset, 32
	.equ strincr, 64

	// pre-load twiddle factors to FPU registers
	vldm twiddle_ptr!, {s8-s22}

	add.w tmp, poly, #8*strincr
	vmov s8, tmp
	1:
		vmov s23, poly
		// load a1, a3, ..., a15
		load poly, poly0, poly1, poly2, poly3, #offset, #distance/4+offset, #2*distance/4+offset, #3*distance/4+offset
		load poly, poly4, poly5, poly6, poly7, #distance+offset, #5*distance/4+offset, #6*distance/4+offset, #7*distance/4+offset

		movw qa, #26632

		// NTT on a1, a3, ..., a15   
		// twiddle2 is used as tmp2
		_3_layer_double_inv_CT_16_plant_light poly0, poly1, poly2, poly3, poly4, poly5, poly6, poly7, s10, s12, s13, s14, twiddle1, twiddle2, q, qa, tmp

		// multiply coeffs by layer 4 twiddles for later use
		// vmov twiddle1, s15 
		vmov twiddle2, s16
		// mul_twiddle_plant poly0, twiddle1, tmp, q, qa // could be omitted but kept for reduction only
		mul_twiddle_plant poly1, twiddle2, tmp, q, qa

		vmov twiddle1, s17 
		vmov twiddle2, s18
		mul_twiddle_plant poly2, twiddle1, tmp, q, qa
		mul_twiddle_plant poly3, twiddle2, tmp, q, qa

		vmov twiddle1, s19 
		vmov twiddle2, s20
		mul_twiddle_plant poly4, twiddle1, tmp, q, qa
		mul_twiddle_plant poly5, twiddle2, tmp, q, qa

		vmov twiddle1, s21 
		vmov twiddle2, s22
		mul_twiddle_plant poly6, twiddle1, tmp, q, qa
		mul_twiddle_plant poly7, twiddle2, tmp, q, qa

		vmov s0, poly0 // a1
		vmov s1, poly1 // a3
		vmov s2, poly2 // a5
		vmov s3, poly3 // a7
		vmov s4, poly4 // a9
		vmov s5, poly5 // a11
		vmov s6, poly6 // a13
		vmov s7, poly7 // a15
		// 0.5q
		// ----------

		vmov poly, s23
		// load a0, a2, ..., a14
		load poly, poly0, poly1, poly2, poly3, #0, #distance/4, #2*distance/4, #3*distance/4
		load poly, poly4, poly5, poly6, poly7, #distance, #5*distance/4, #6*distance/4, #7*distance/4
		
		movw qa, #26632
		// NTT on a0, a2, ..., a14
		// twiddle2 is used as tmp2
		_3_layer_double_inv_CT_16_plant_light poly0, poly1, poly2, poly3, poly4, poly5, poly6, poly7, s10, s12, s13, s14, twiddle1, twiddle2, q, qa, tmp
		// 1,3,5,7: <5q; 0,2,4,6:<1q
		// layer 4 - 1
		// addsub: (a2, a6, a10, a14), (a3, a7, a11, a15)
		vmov poly, s23
		vmov twiddle2, s1 // load a3
		uadd16 tmp, poly1, twiddle2
		usub16 poly1, poly1, twiddle2
		str.w tmp, [poly, #1*distance/4]
		str.w poly1, [poly, #1*distance/4+offset]

		vmov twiddle2, s3 // load a7
		uadd16 tmp, poly3, twiddle2
		usub16 poly3, poly3, twiddle2
		str.w tmp, [poly, #3*distance/4]
		str.w poly3, [poly, #3*distance/4+offset]
		
		vmov twiddle2, s5 // load a11
		uadd16 tmp, poly5, twiddle2
		usub16 poly5, poly5, twiddle2
		str.w tmp, [poly, #5*distance/4]
		str.w poly5, [poly, #5*distance/4+offset]
		
		vmov twiddle2, s7 // load a15
		uadd16 tmp, poly7, twiddle2
		usub16 poly7, poly7, twiddle2
		str.w tmp, [poly, #7*distance/4]
		str.w poly7, [poly, #7*distance/4+offset]
		//1,3,5,7: < 5.5q

		// layer 4 - 2    
		// addsub: (a0, a4, a8, a12), (a1, a5, a9, a13)
		vmov poly3, s2 // load a5
		uadd16 tmp, poly2, poly3
		usub16 twiddle2, poly2, poly3
		str.w tmp, [poly, #2*distance/4]
		str.w twiddle2, [poly, #2*distance/4+offset]

		vmov poly5, s4 // load a9
		uadd16 tmp, poly4, poly5
		usub16 twiddle2, poly4, poly5
		str.w tmp, [poly, #4*distance/4]
		str.w twiddle2, [poly, #4*distance/4+offset]

		vmov poly7, s6 // load a13
		uadd16 tmp, poly6, poly7
		usub16 twiddle2, poly6, poly7
		str.w tmp, [poly, #6*distance/4]
		str.w twiddle2, [poly, #6*distance/4+offset]
		
		vmov poly1, s0 // load a1
		uadd16 tmp, poly0, poly1
		usub16 twiddle2, poly0, poly1
		str.w twiddle2, [poly, #offset]    
		str.w tmp, [poly], #strincr // increase 2*8*4 = 64 (2 * 8 loads of 4 bytes each)
		//0,2,4,6: < 1.5q
	vmov tmp, s8
	cmp.w poly, tmp
	bne.w 1b

	sub.w poly, poly, #512  

	### LAYER 3+2+1

	.equ distance, distance*16
	.equ strincr, 4

	// ITER 0
	vmov s6, poly
	load poly, poly0, poly1, poly2, poly3, #0, #distance/4, #2*distance/4, #3*distance/4
	load poly, poly4, poly5, poly6, poly7, #distance, #5*distance/4, #6*distance/4, #7*distance/4

	vldm twiddle_ptr!, {s0-s5}
	movw qa, #26632
	fullplant poly0, poly1, poly2, poly3, poly4, poly5, poly6, poly7, tmp, q, qa, twiddle1
	// twiddle2 is used as tmp2
	_3_layer_double_inv_CT_16_plant_light poly0, poly1, poly2, poly3, poly4, poly5, poly6, poly7, s1, s3, s4, s5, twiddle1, twiddle2, q, qa, tmp

	// twisting
	_3_layer_double_inv_twist_16_plant poly0, poly1, poly2, poly3, poly4, poly5, poly6, poly7, twiddle1, twiddle2, twiddle_ptr, q, qa, tmp
	
	vmov poly, s6
	store poly, poly4, poly5, poly6, poly7, #distance, #5*distance/4, #6*distance/4, #7*distance/4
	str.w poly1, [poly, #distance/4]
	str.w poly2, [poly, #2*distance/4]
	str.w poly3, [poly, #3*distance/4]
	str.w poly0, [poly], #4

	// ITER 1-15
	add.w tmp, poly, #strincr*3*(5)
	vmov s14, tmp
	2:
		vmov s6, poly
		// polys upto 5.5q
		load poly, poly0, poly1, poly2, poly3, #0, #distance/4, #2*distance/4, #3*distance/4
		load poly, poly4, poly5, poly6, poly7, #distance, #5*distance/4, #6*distance/4, #7*distance/4
		
		movw qa, #26632
		_3_layer_double_inv_CT_16_plant poly0, poly1, poly2, poly3, poly4, poly5, poly6, poly7, twiddle1, twiddle2, twiddle_ptr, q, qa, tmp

		// twisting
		_3_layer_double_inv_twist_16_plant poly0, poly1, poly2, poly3, poly4, poly5, poly6, poly7, twiddle1, twiddle2, twiddle_ptr, q, qa, tmp

		vmov poly, s6
		store poly, poly4, poly5, poly6, poly7, #distance, #5*distance/4, #6*distance/4, #7*distance/4
		str.w poly1, [poly, #distance/4]
		str.w poly2, [poly, #2*distance/4]
		str.w poly3, [poly, #3*distance/4]
		str.w poly0, [poly], #4

	vmov tmp, s14
	cmp.w poly, tmp
	bne.w 2b

	vpop {s16-s23}
	.unreq poly
	.unreq twiddle_ptr
	.unreq poly0
	.unreq poly1
	.unreq poly2
	.unreq poly3
	.unreq poly4
	.unreq poly5
	.unreq poly6
	.unreq poly7
	.unreq twiddle1
	.unreq twiddle2
	.unreq q
	.unreq qa
	.unreq tmp
	pop {r4-r11, pc}

/******************************************************************************
* Integrating the improved Plantard arithmetic into Kyber.
*
* Efficient Plantard arithmetic enables a faster Kyber implementation with the 
* same stack usage.
*
* See the paper at https://eprint.iacr.org/2022/956.pdf for more details.
*
* @author   Junhao Huang, BNU-HKBU United International College, Zhuhai, China
*           jhhuang_nuaa@126.com
*
* @date     September 2022
******************************************************************************/



.syntax unified
.cpu cortex-m4
.thumb

.thumb_func
.global asm_barrett_reduce
.type asm_barrett_reduce,%function
.align 2
asm_barrett_reduce:
	push    {r4-r11, r14}

	poly        .req r0
	poly0       .req r1
	poly1       .req r2
	poly2       .req r3
	poly3       .req r4
	poly4       .req r5
	poly5       .req r6
	poly6       .req r7
	poly7       .req r8
	loop        .req r9
	barrettconst .req r10
	q           .req r11
	tmp         .req r12
	tmp2        .req r14

	movw barrettconst, #20159
	movw q, #3329

	movw loop, #16
	1:
		ldm poly, {poly0-poly7}

		doublebarrett poly0, tmp, tmp2, q, barrettconst
		doublebarrett poly1, tmp, tmp2, q, barrettconst
		doublebarrett poly2, tmp, tmp2, q, barrettconst
		doublebarrett poly3, tmp, tmp2, q, barrettconst
		doublebarrett poly4, tmp, tmp2, q, barrettconst
		doublebarrett poly5, tmp, tmp2, q, barrettconst
		doublebarrett poly6, tmp, tmp2, q, barrettconst
		doublebarrett poly7, tmp, tmp2, q, barrettconst

		stm poly!, {poly0-poly7}

	subs.w loop, loop, #1
	bne.w 1b

	.unreq poly        
	.unreq poly0       
	.unreq poly1       
	.unreq poly2       
	.unreq poly3       
	.unreq poly4       
	.unreq poly5       
	.unreq poly6       
	.unreq poly7       
	.unreq loop        
	.unreq barrettconst
	.unreq q           
	.unreq tmp         
	.unreq tmp2        

	pop     {r4-r11, pc}

.thumb_func
.global asm_fromplant
.type asm_fromplant,%function
.align 2
asm_fromplant:
	push    {r4-r11, r14}

	poly        .req r0
	poly0       .req r1
	poly1       .req r2
	poly2       .req r3
	poly3       .req r4
	poly4       .req r5
	poly5       .req r6
	poly6       .req r7
	poly7       .req r8
	loop        .req r9
	plantconst  .req r10
	q           .req r11
	qa          .req r12
	tmp         .req r14
	
	movw qa, #26632
	movt q, #3329
	
	### movt qinv, #3327
	### plant_constant=(Plant_const^2%M)*(p^-1) % 2^32
	movw plantconst, #20396
	movt plantconst, #38900
	movw loop, #16
	1:
		ldm poly, {poly0-poly7}

		doubleplant poly0, tmp, q, qa, plantconst
		doubleplant poly1, tmp, q, qa, plantconst
		doubleplant poly2, tmp, q, qa, plantconst
		doubleplant poly3, tmp, q, qa, plantconst
		doubleplant poly4, tmp, q, qa, plantconst
		doubleplant poly5, tmp, q, qa, plantconst
		doubleplant poly6, tmp, q, qa, plantconst
		doubleplant poly7, tmp, q, qa, plantconst
	
		stm poly!, {poly0-poly7}

	subs.w loop, loop, #1
	bne.w 1b

	.unreq poly        
	.unreq poly0       
	.unreq poly1       
	.unreq poly2       
	.unreq poly3       
	.unreq poly4       
	.unreq poly5       
	.unreq poly6       
	.unreq poly7       
	.unreq loop        
	.unreq plantconst  
	.unreq q           
	.unreq qa          
	.unreq tmp         
	pop     {r4-r11, pc}

.syntax unified
.cpu cortex-m4
.thumb

.align 2
.thumb_func
.global pointwise_sub
.type pointwise_sub, %function
pointwise_sub:
  push {r4-r11, lr}

  movw r14, #25
  1:
    ldm r1!, {r3-r7}
    ldm r2!, {r8-r12}
    usub16 r3, r3, r8
    usub16 r4, r4, r9
    usub16 r5, r5, r10
    usub16 r6, r6, r11
    usub16 r7, r7, r12
    stm r0!, {r3-r7}

    subs.w r14, r14, #1
  bne.w 1b

  ldm r1!, {r3-r5}
  ldm r2!, {r8-r10}
  usub16 r3, r3, r8
  usub16 r4, r4, r9
  usub16 r5, r5, r10
  stm r0!, {r3-r5}
  pop {r4-r11, pc}


.align 2
.thumb_func
.global pointwise_add
.type pointwise_add, %function
pointwise_add:
  push {r4-r11, lr}

  movw r14, #25
  1:
    ldm r1!, {r3-r7}
    ldm r2!, {r8-r12}
    uadd16 r3, r3, r8
    uadd16 r4, r4, r9
    uadd16 r5, r5, r10
    uadd16 r6, r6, r11
    uadd16 r7, r7, r12
    stm r0!, {r3-r7}

    subs.w r14, r14, #1
  bne.w 1b

  ldm r1!, {r3-r5}
  ldm r2!, {r8-r10}
  uadd16 r3, r3, r8
  uadd16 r4, r4, r9
  uadd16 r5, r5, r10
  stm r0!, {r3-r5}
  pop {r4-r11, pc}


.syntax unified
.cpu cortex-m4
.thumb

// void basemul_asm_opt_16_32(int32_t *, const int16_t *, const int16_t *, const int16_t *)
.thumb_func
.global basemul_asm_opt_16_32
.type basemul_asm_opt_16_32, %function
.align 2
basemul_asm_opt_16_32:
  push {r4-r11, lr}
  
  rptr_tmp  .req r0
  aptr      .req r1
  bptr      .req r2
  aprimeptr .req r3
  poly0     .req r4
  poly1     .req r6
  poly2     .req r5
  poly3     .req r7
  q         .req r8
  qa        .req r9
  qinv      .req r10
  tmp       .req r11
  tmp2      .req r12
  loop      .req r14

  //movw qa, #26632
	//movt  q, #3329
	### qinv=0x6ba8f301
	//movw qinv, #62209
	//movt qinv, #27560

  movw loop, #64
  1:
    ldr poly0, [aptr], #4
    ldr poly1, [bptr], #4
    ldr poly2, [aptr], #4
    ldr poly3, [bptr], #4
    ldr.w tmp, [aprimeptr, #4]
    ldr tmp2, [aprimeptr], #8
    
    // (poly0_t * zeta) * poly1_t + poly0_b * poly1_b
    smuad tmp2, tmp2, poly1
    str tmp2, [rptr_tmp], #4

    // poly1_t * poly0_b + poly1_b * poly0_t
    smuadx tmp2, poly0, poly1
    str tmp2, [rptr_tmp], #4
    
    smuad tmp2, tmp, poly3
    str tmp2, [rptr_tmp], #4

    smuadx tmp2, poly2, poly3
    str tmp2, [rptr_tmp], #4

    subs.w loop, loop, #1
  bne.w 1b

  .unreq rptr
  .unreq aptr
  .unreq bptr
  .unreq aprimeptr
  .unreq poly0
  .unreq poly1
  .unreq res0
  .unreq res1
  .unreq q
  .unreq qa
  .unreq qinv
  .unreq tmp2
  .unreq rptr_tmp
  .unreq loop
  pop {r4-r11, pc}

// void basemul_asm_acc_opt_32_32(int32_t *, const int16_t *, const int16_t *, const int16_t *)
.thumb_func
.global basemul_asm_acc_opt_32_32
.type basemul_asm_acc_opt_32_32, %function
.align 2
basemul_asm_acc_opt_32_32:
  push {r4-r11, lr}

  rptr_tmp  .req r0
  aptr      .req r1
  bptr      .req r2
  aprimeptr .req r3
  poly0     .req r4
  poly1     .req r6
  res0      .req r5
  res1      .req r7
  q         .req r8
  qa        .req r9
  qinv      .req r10
  tmp       .req r11
  tmp2      .req r12
  loop      .req r14

  //movw qa, #26632
	//movt  q, #3329
	### qinv=0x6ba8f301
	//movw qinv, #62209
	//movt qinv, #27560

  movw loop, #64
  1:
    ldr poly0, [aptr], #4
    ldr poly1, [bptr], #4
    ldr.w res0, [rptr_tmp]
    ldr tmp2, [aprimeptr], #4
    ldr.w res1, [rptr_tmp, #4]

    // (poly0_t * zeta) * poly1_t + poly0_b * poly0_t + res
    smlad tmp2, tmp2, poly1, res0
    str tmp2, [rptr_tmp], #4

    // poly1_t * poly0_b + poly1_b * poly0_t + res
    smladx tmp, poly0, poly1, res1
    str tmp, [rptr_tmp], #4

    ldr poly0, [aptr], #4
    ldr poly1, [bptr], #4
    ldr.w res0, [rptr_tmp]
    ldr tmp2, [aprimeptr], #4
    ldr.w res1, [rptr_tmp, #4]
    
    smlad tmp2, tmp2, poly1, res0
    str tmp2, [rptr_tmp], #4

    smladx tmp, poly0, poly1, res1
    str tmp, [rptr_tmp], #4

    subs.w loop, loop, #1
  bne.w 1b

  .unreq rptr_tmp
  .unreq aptr
  .unreq bptr
  .unreq aprimeptr
  .unreq poly0
  .unreq poly1
  .unreq poly2
  .unreq poly3
  .unreq q
  .unreq qa
  .unreq qinv
  .unreq tmp
  .unreq tmp2
  .unreq loop
  pop {r4-r11, pc}


// void basemul_asm_acc_opt_32_16(int16_t *, const int16_t *, const int16_t *, const int16_t *, const int32_t *)
.thumb_func
.global basemul_asm_acc_opt_32_16
.type basemul_asm_acc_opt_32_16, %function
.align 2
basemul_asm_acc_opt_32_16:
  push {r4-r11, lr}

  rptr      .req r0
  aptr      .req r1
  bptr      .req r2
  aprimeptr .req r3
  poly0     .req r4
  poly1     .req r6
  res0      .req r5
  res1      .req r7
  q         .req r8
  qa        .req r9
  qinv      .req r10
  //tmp       .req r11
  tmp2      .req r12
  rptr_tmp  .req r11
  loop      .req r14

  movw qa, #26632
	movt  q, #3329
	### qinv=0x6ba8f301
	movw qinv, #62209
	movt qinv, #27560

  ldr rptr_tmp, [sp, #9*4]
  movw loop, #64
  1:
    ldr poly0, [aptr], #4
    ldr poly1, [bptr], #4
    ldr.w res0, [rptr_tmp], #4
    ldr tmp2, [aprimeptr], #4
    ldr.w res1, [rptr_tmp], #4

    // (poly0_t * zeta) * poly1_t + poly0_b * poly0_b + res
    smlad res0, tmp2, poly1, res0
    plant_red q, qa, qinv, res0

    // poly1_t * poly0_b + poly1_b * poly0_t + res
    smladx res1, poly0, poly1, res1
    plant_red q, qa, qinv, res1

    pkhtb res0, res1, res0, asr#16
    str res0, [rptr], #4

    ldr poly0, [aptr], #4
    ldr poly1, [bptr], #4
    ldr.w res0, [rptr_tmp], #4
    ldr tmp2, [aprimeptr], #4     
    ldr.w res1, [rptr_tmp], #4
    
    smlad res0, tmp2, poly1, res0
    plant_red q, qa, qinv, res0
    
    smladx res1, poly0, poly1, res1
    plant_red q, qa, qinv, res1

    pkhtb res0, res1, res0, asr#16
    str res0, [rptr], #4

    subs.w loop, loop, #1
  bne.w 1b

  .unreq rptr
  .unreq aptr
  .unreq bptr
  .unreq aprimeptr
  .unreq poly0
  .unreq poly1
  .unreq res0
  .unreq res1
  .unreq q
  .unreq qa
  .unreq qinv
  .unreq tmp2
  .unreq rptr_tmp
  .unreq loop
  pop {r4-r11, pc}


// void basemul_asm(int16_t *r, const int16_t *a, const int16_t *b, const int32_t *zetas)
.thumb_func
.global basemul_asm
.type basemul_asm, %function
.align 2
basemul_asm:
	push {r4-r11, lr}

	rptr    .req r0
	aptr    .req r1
	bptr    .req r2
	zetaptr .req r3
	poly0   .req r4
	poly1   .req r6
	poly2   .req r5
	poly3   .req r7
	q       .req r8
	qa      .req r14
	qinv    .req r9
	tmp     .req r10
	tmp2    .req r11
	zeta    .req r12
	loop    .req r14

	movw q, #0
	movt q, #3329
	### qinv=0x6ba8f301
	movw qinv, #62209
	movt qinv, #27560

	movw loop, #64
	1:
	vmov s0, loop
	movw qa, #26632
			
	ldrd poly0, poly2, [aptr], #8
	ldrd poly1, poly3, [bptr], #8 

	ldr.w zeta, [zetaptr], #4

	// basemul(r->coeffs + 4 * i, a->coeffs + 4 * i, b->coeffs + 4 * i, zetas[64 + i]);
	smulwt tmp, zeta, poly1 
	smlabt tmp, tmp, q, qa  
	smultt tmp, poly0, tmp  
	smlabb tmp, poly0, poly1, tmp 
	plant_red q, qa, qinv, tmp
	// r[0] in upper half of tmp
	
	smuadx tmp2, poly0, poly1 
	plant_red q, qa, qinv, tmp2
	// r[1] in upper half of tmp2
	pkhtb tmp, tmp2, tmp, asr#16
	str tmp, [rptr], #4

	neg zeta, zeta

	// basemul(r->coeffs + 4 * i + 2, a->coeffs + 4 * i + 2, b->coeffs + 4 * i + 2, - zetas[64 + i]);
	smulwt tmp, zeta, poly3 
	smlabt tmp, tmp, q, qa  
	smultt tmp, poly2, tmp  
	smlabb tmp, poly2, poly3, tmp 
	plant_red q, qa, qinv, tmp
	// r[0] in upper half of tmp
	
	smuadx tmp2, poly2, poly3 
	plant_red q, qa, qinv, tmp2
	// r[1] in upper half of tmp2
	pkhtb tmp, tmp2, tmp, asr#16
	str tmp, [rptr], #4
		
	vmov loop, s0
	subs.w loop, loop, #1
	bne.w 1b

	.unreq rptr   
	.unreq aptr   
	.unreq bptr   
	.unreq zetaptr
	.unreq poly0  
	.unreq poly1  
	.unreq poly2  
	.unreq poly3  
	.unreq q      
	.unreq qa     
	.unreq qinv   
	.unreq tmp    
	.unreq tmp2   
	.unreq zeta   
	.unreq loop   

	pop {r4-r11, pc}


// void basemul_asm_acc(int16_t *r, const int16_t *a, const int16_t *b, const int32_t *zetas)
.thumb_func
.global basemul_asm_acc
.type basemul_asm_acc, %function
.align 2
basemul_asm_acc:
	push {r4-r11, lr}

	rptr    .req r0
	aptr    .req r1
	bptr    .req r2
	zetaptr .req r3
	poly0   .req r4
	poly1   .req r6
	poly2   .req r5
	poly3   .req r7
	q       .req r8
	qa      .req r14
	qinv    .req r9
	tmp     .req r10
	tmp2    .req r11
	zeta    .req r12
	loop    .req r14

	movw q, #0
	movt q, #3329
	### qinv=0x6ba8f301
	movw qinv, #62209
	movt qinv, #27560

	movw loop, #64
	1:
		vmov s0, loop
		movw qa, #26632

	ldrd poly0, poly2, [aptr], #8
	ldrd poly1, poly3, [bptr], #8

	ldr.w zeta, [zetaptr], #4

	// basemul(r->coeffs + 4 * i, a->coeffs + 4 * i, b->coeffs + 4 * i, zetas[64 + i]);
	smulwt tmp, zeta, poly1 
	smlabt tmp, tmp, q, qa  
	smultt tmp, poly0, tmp  
	smlabb tmp, poly0, poly1, tmp 
	plant_red q, qa, qinv, tmp
	// r[0] in upper half of tmp
	
	smuadx tmp2, poly0, poly1 
	plant_red q, qa, qinv, tmp2
	// r[1] in upper half of tmp2
	pkhtb tmp, tmp2, tmp, asr#16
	
	ldr.w tmp2, [rptr]
	uadd16 tmp, tmp, tmp2
	str.w tmp, [rptr], #4

	neg zeta, zeta

	// basemul(r->coeffs + 4 * i + 2, a->coeffs + 4 * i + 2, b->coeffs + 4 * i + 2, - zetas[64 + i]);
	smulwt tmp, zeta, poly3 
	smlabt tmp, tmp, q, qa  
	smultt tmp, poly2, tmp  
	smlabb tmp, poly2, poly3, tmp 
	plant_red q, qa, qinv, tmp
	// r[0] in upper half of tmp
	
	smuadx tmp2, poly2, poly3 
	plant_red q, qa, qinv, tmp2
	// r[1] in upper half of tmp2
	pkhtb tmp, tmp2, tmp, asr#16
	
	ldr.w tmp2, [rptr]
	uadd16 tmp, tmp, tmp2
	str.w tmp, [rptr], #4

	vmov loop, s0
	subs.w loop, loop, #1
	bne.w 1b

	.unreq rptr    
	.unreq aptr    
	.unreq bptr    
	.unreq zetaptr 
	.unreq poly0   
	.unreq poly1   
	.unreq poly2   
	.unreq poly3   
	.unreq q       
	.unreq qa      
	.unreq qinv    
	.unreq tmp     
	.unreq tmp2    
	.unreq zeta    
	.unreq loop    

	pop {r4-r11, pc}
@ Constant-time Poly1305 block multiplication using UMAAL on ARMv7E-M / ARMv8-M.
@
@ Computes (h * r) mod (2^130 - 5) using 26-bit limbs with 5 single-cycle UMAALs per limb.

	.syntax unified
	.thumb
	.arch armv7e-m
	.text
	.align 2

@ void poly1305_mul_reduce_umaal(uint32_t h[5], const uint32_t r[5], const uint32_t s[4]);
@ in: r0 = &h[0], r1 = &r[0], r2 = &s[0]
	.global poly1305_mul_reduce_umaal
	.type poly1305_mul_reduce_umaal, %function
poly1305_mul_reduce_umaal:
	push {r4-r11, lr}
	sub sp, sp, #56
	str r0, [sp, #48]

	@ Load h0-h4 into r3-r7
	ldm r0, {r3-r7}

	@ Load s0-s3 (s1..s4) into stack sp[0..16]
	ldr r8, [r2]
	ldr r9, [r2, #4]
	ldr r10, [r2, #8]
	ldr r11, [r2, #12]
	stm sp, {r8-r11}

	@ --- d0 = h0*r0 + h1*s4 + h2*s3 + h3*s2 + h4*s1 ---
	movs r8, #0
	movs r9, #0
	ldr r12, [r1]        @ r0
	umlal r8, r9, r3, r12
	ldr r12, [sp, #12]   @ s4
	umlal r8, r9, r4, r12
	ldr r12, [sp, #8]    @ s3
	umlal r8, r9, r5, r12
	ldr r12, [sp, #4]    @ s2
	umlal r8, r9, r6, r12
	ldr r12, [sp]        @ s1
	umlal r8, r9, r7, r12
	strd r8, r9, [sp, #16]

	@ --- d1 = h0*r1 + h1*r0 + h2*s4 + h3*s3 + h4*s2 ---
	movs r8, #0
	movs r9, #0
	ldr r12, [r1, #4]    @ r1
	umlal r8, r9, r3, r12
	ldr r12, [r1]        @ r0
	umlal r8, r9, r4, r12
	ldr r12, [sp, #12]   @ s4
	umlal r8, r9, r5, r12
	ldr r12, [sp, #8]    @ s3
	umlal r8, r9, r6, r12
	ldr r12, [sp, #4]    @ s2
	umlal r8, r9, r7, r12
	strd r8, r9, [sp, #24]

	@ --- d2 = h0*r2 + h1*r1 + h2*r0 + h3*s4 + h4*s3 ---
	movs r8, #0
	movs r9, #0
	ldr r12, [r1, #8]    @ r2
	umlal r8, r9, r3, r12
	ldr r12, [r1, #4]    @ r1
	umlal r8, r9, r4, r12
	ldr r12, [r1]        @ r0
	umlal r8, r9, r5, r12
	ldr r12, [sp, #12]   @ s4
	umlal r8, r9, r6, r12
	ldr r12, [sp, #8]    @ s3
	umlal r8, r9, r7, r12
	strd r8, r9, [sp, #32]

	@ --- d3 = h0*r3 + h1*r2 + h2*r1 + h3*r0 + h4*s4 ---
	movs r8, #0
	movs r9, #0
	ldr r12, [r1, #12]   @ r3
	umlal r8, r9, r3, r12
	ldr r12, [r1, #8]    @ r2
	umlal r8, r9, r4, r12
	ldr r12, [r1, #4]    @ r1
	umlal r8, r9, r5, r12
	ldr r12, [r1]        @ r0
	umlal r8, r9, r6, r12
	ldr r12, [sp, #12]   @ s4
	umlal r8, r9, r7, r12
	strd r8, r9, [sp, #40]

	@ --- d4 = h0*r4 + h1*r3 + h2*r2 + h3*r1 + h4*r0 ---
	movs r8, #0
	movs r9, #0
	ldr r12, [r1, #16]   @ r4
	umlal r8, r9, r3, r12
	ldr r12, [r1, #12]   @ r3
	umlal r8, r9, r4, r12
	ldr r12, [r1, #8]    @ r2
	umlal r8, r9, r5, r12
	ldr r12, [r1, #4]    @ r1
	umlal r8, r9, r6, r12
	ldr r12, [r1]        @ r0
	umlal r8, r9, r7, r12

	@ --- Sequential reduction ---
	@ d0:
	ldrd r0, r1, [sp, #16]
	ubfx r3, r0, #0, #26
	lsrs r10, r0, #26
	orr r10, r10, r1, lsl #6

	@ d1:
	ldrd r0, r1, [sp, #24]
	adds r0, r0, r10
	adcs r1, r1, #0
	ubfx r4, r0, #0, #26
	lsrs r10, r0, #26
	orr r10, r10, r1, lsl #6

	@ d2:
	ldrd r0, r1, [sp, #32]
	adds r0, r0, r10
	adcs r1, r1, #0
	ubfx r5, r0, #0, #26
	lsrs r10, r0, #26
	orr r10, r10, r1, lsl #6

	@ d3:
	ldrd r0, r1, [sp, #40]
	adds r0, r0, r10
	adcs r1, r1, #0
	ubfx r6, r0, #0, #26
	lsrs r10, r0, #26
	orr r10, r10, r1, lsl #6

	@ d4 (already in r8, r9):
	adds r8, r8, r10
	adcs r9, r9, #0
	ubfx r7, r8, #0, #26
	lsrs r10, r8, #26
	orr r10, r10, r9, lsl #6

	@ --- Wrap carry: h0 += c4 * 5 ---
	add r12, r10, r10, lsl #2 @ r12 = c4 * 5
	adds r3, r3, r12
	lsrs r12, r3, #26
	ubfx r3, r3, #0, #26
	adds r4, r4, r12          @ h1 += c

	@ Store h0..h4 back to *r0
	ldr r0, [sp, #48]
	stm r0, {r3-r7}

	add sp, sp, #56
	pop {r4-r11, pc}
	.size poly1305_mul_reduce_umaal, .-poly1305_mul_reduce_umaal

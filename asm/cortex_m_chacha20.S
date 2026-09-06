@ Constant-time ChaCha20 block function for ARMv7-M / ARMv7E-M / ARMv8-M.
@
@ Keeps 8 state words in registers (r5-r12) and 8 in memory (out[0..3] and out[12..15]),
@ processing all 20 rounds without stack spills.

	.syntax unified
	.thumb
	.text
	.align 2

@ void chacha20_block_cortex_m(uint32_t out[16], const uint32_t state[16]);
@ in: r0 = &out[0], r1 = &state[0]
	.global chacha20_block_cortex_m
	.type chacha20_block_cortex_m, %function
chacha20_block_cortex_m:
	push {r4-r11, lr}
	push {r0, r1}        @ preserve base out and state pointers

	@ Copy state[0..3] to out[0..3]
	ldm r1!, {r4-r7}
	stm r0, {r4-r7}

	@ Copy state[12..15] to out[12..15]
	add r12, r0, #48
	add r14, r1, #32     @ r1 is at state[4], +32 = state[12]
	ldm r14, {r4-r7}
	stm r12, {r4-r7}

	@ Load state[4..11] into registers r5-r12
	ldm r1, {r5-r12}

	movs r4, #10         @ 10 double rounds = 20 rounds

.Lround_loop:
	@ ===== Column Round =====
	@ Q1 (0, 4, 8, 12)
	ldr r1, [r0, #0]
	ldr r2, [r0, #48]
	add r1, r1, r5
	eor r2, r2, r1
	ror r2, r2, #16
	add r9, r9, r2
	eor r5, r5, r9
	ror r5, r5, #20
	add r1, r1, r5
	eor r2, r2, r1
	ror r2, r2, #24
	add r9, r9, r2
	eor r5, r5, r9
	ror r5, r5, #25
	str r1, [r0, #0]
	str r2, [r0, #48]

	@ Q2 (1, 5, 9, 13)
	ldr r1, [r0, #4]
	ldr r2, [r0, #52]
	add r1, r1, r6
	eor r2, r2, r1
	ror r2, r2, #16
	add r10, r10, r2
	eor r6, r6, r10
	ror r6, r6, #20
	add r1, r1, r6
	eor r2, r2, r1
	ror r2, r2, #24
	add r10, r10, r2
	eor r6, r6, r10
	ror r6, r6, #25
	str r1, [r0, #4]
	str r2, [r0, #52]

	@ Q3 (2, 6, 10, 14)
	ldr r1, [r0, #8]
	ldr r2, [r0, #56]
	add r1, r1, r7
	eor r2, r2, r1
	ror r2, r2, #16
	add r11, r11, r2
	eor r7, r7, r11
	ror r7, r7, #20
	add r1, r1, r7
	eor r2, r2, r1
	ror r2, r2, #24
	add r11, r11, r2
	eor r7, r7, r11
	ror r7, r7, #25
	str r1, [r0, #8]
	str r2, [r0, #56]

	@ Q4 (3, 7, 11, 15)
	ldr r1, [r0, #12]
	ldr r2, [r0, #60]
	add r1, r1, r8
	eor r2, r2, r1
	ror r2, r2, #16
	add r12, r12, r2
	eor r8, r8, r12
	ror r8, r8, #20
	add r1, r1, r8
	eor r2, r2, r1
	ror r2, r2, #24
	add r12, r12, r2
	eor r8, r8, r12
	ror r8, r8, #25
	str r1, [r0, #12]
	str r2, [r0, #60]

	@ ===== Diagonal Round =====
	@ Q5 (0, 5, 10, 15)
	ldr r1, [r0, #0]
	ldr r2, [r0, #60]
	add r1, r1, r6
	eor r2, r2, r1
	ror r2, r2, #16
	add r11, r11, r2
	eor r6, r6, r11
	ror r6, r6, #20
	add r1, r1, r6
	eor r2, r2, r1
	ror r2, r2, #24
	add r11, r11, r2
	eor r6, r6, r11
	ror r6, r6, #25
	str r1, [r0, #0]
	str r2, [r0, #60]

	@ Q6 (1, 6, 11, 12)
	ldr r1, [r0, #4]
	ldr r2, [r0, #48]
	add r1, r1, r7
	eor r2, r2, r1
	ror r2, r2, #16
	add r12, r12, r2
	eor r7, r7, r12
	ror r7, r7, #20
	add r1, r1, r7
	eor r2, r2, r1
	ror r2, r2, #24
	add r12, r12, r2
	eor r7, r7, r12
	ror r7, r7, #25
	str r1, [r0, #4]
	str r2, [r0, #48]

	@ Q7 (2, 7, 8, 13)
	ldr r1, [r0, #8]
	ldr r2, [r0, #52]
	add r1, r1, r8
	eor r2, r2, r1
	ror r2, r2, #16
	add r9, r9, r2
	eor r8, r8, r9
	ror r8, r8, #20
	add r1, r1, r8
	eor r2, r2, r1
	ror r2, r2, #24
	add r9, r9, r2
	eor r8, r8, r9
	ror r8, r8, #25
	str r1, [r0, #8]
	str r2, [r0, #52]

	@ Q8 (3, 4, 9, 14)
	ldr r1, [r0, #12]
	ldr r2, [r0, #56]
	add r1, r1, r5
	eor r2, r2, r1
	ror r2, r2, #16
	add r10, r10, r2
	eor r5, r5, r10
	ror r5, r5, #20
	add r1, r1, r5
	eor r2, r2, r1
	ror r2, r2, #24
	add r10, r10, r2
	eor r5, r5, r10
	ror r5, r5, #25
	str r1, [r0, #12]
	str r2, [r0, #56]

	subs r4, r4, #1
	bne .Lround_loop

	@ Store scrambled words 4..11 into out[4..11]
	add r1, r0, #16
	stm r1, {r5-r12}

	@ Pop base pointers
	pop {r0, r1}

	@ Add initial state to scrambled state: out[0..15] += state[0..15]
	@ Chunk 0: words 0..3
	ldm r1!, {r4-r7}
	ldm r0, {r8-r11}
	add r8, r8, r4
	add r9, r9, r5
	add r10, r10, r6
	add r11, r11, r7
	stm r0!, {r8-r11}

	@ Chunk 1: words 4..7
	ldm r1!, {r4-r7}
	ldm r0, {r8-r11}
	add r8, r8, r4
	add r9, r9, r5
	add r10, r10, r6
	add r11, r11, r7
	stm r0!, {r8-r11}

	@ Chunk 2: words 8..11
	ldm r1!, {r4-r7}
	ldm r0, {r8-r11}
	add r8, r8, r4
	add r9, r9, r5
	add r10, r10, r6
	add r11, r11, r7
	stm r0!, {r8-r11}

	@ Chunk 3: words 12..15
	ldm r1!, {r4-r7}
	ldm r0, {r8-r11}
	add r8, r8, r4
	add r9, r9, r5
	add r10, r10, r6
	add r11, r11, r7
	stm r0!, {r8-r11}

	pop {r4-r11, pc}
	.size chacha20_block_cortex_m, .-chacha20_block_cortex_m

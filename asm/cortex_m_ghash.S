/* Copyright 2010-2025 The OpenSSL Project Authors. All Rights Reserved. */
/* Ported to Cortex-M Thumb-2 for mcu-crypto-asm */
.syntax unified
.thumb
.text

.type rem_4bit,%object
.align 5
rem_4bit:
	.short 0x0000, 0x1C20, 0x3840, 0x2460
	.short 0x7080, 0x6CA0, 0x48C0, 0x54E0
	.short 0xE100, 0xFD20, 0xD940, 0xC560
	.short 0x9180, 0x8DA0, 0xA9C0, 0xB5E0
.size rem_4bit, .-rem_4bit

.align 2
.thumb_func
.global gcm_ghash_4bit
.type gcm_ghash_4bit, %function
gcm_ghash_4bit:
	adr r12,rem_4bit
	add r3,r2,r3 @ r3 to point at the end
	stmdb sp!,{r3-r11,lr} @ save r3/end too
	ldmia r12,{r4-r11} @ copy rem_4bit ...
	stmdb sp!,{r4-r11} @ ... to stack
	ldrb r12,[r2,#15]
	ldrb r14,[r0,#15]
.Lghash_outer:
	eor r12,r12,r14
	and r14,r12,#0xf0
	and r12,r12,#0x0f
	mov r3,#14
	add r7,r1,r12,lsl#4
	ldmia r7,{r4-r7} @ load Htbl[nlo]
	add r11,r1,r14
	ldrb r12,[r2,#14]
	and r14,r4,#0xf @ rem
	ldmia r11,{r8-r11} @ load Htbl[nhi]
	add r14,r14,r14
	eor r4,r8,r4,lsr#4
	ldrh r8,[sp,r14] @ rem_4bit[rem]
	eor r4,r4,r5,lsl#28
	ldrb r14,[r0,#14]
	eor r5,r9,r5,lsr#4
	eor r5,r5,r6,lsl#28
	eor r6,r10,r6,lsr#4
	eor r6,r6,r7,lsl#28
	eor r7,r11,r7,lsr#4
	eor r12,r12,r14
	and r14,r12,#0xf0
	and r12,r12,#0x0f
	eor r7,r7,r8,lsl#16
.Lghash_inner:
	add r11,r1,r12,lsl#4
	and r12,r4,#0xf @ rem
	subs r3,r3,#1
	add r12,r12,r12
	ldmia r11,{r8-r11} @ load Htbl[nlo]
	eor r4,r8,r4,lsr#4
	eor r4,r4,r5,lsl#28
	eor r5,r9,r5,lsr#4
	eor r5,r5,r6,lsl#28
	ldrh r8,[sp,r12] @ rem_4bit[rem]
	eor r6,r10,r6,lsr#4
	it pl
	ldrbpl r12,[r2,r3]
	eor r6,r6,r7,lsl#28
	eor r7,r11,r7,lsr#4
	add r11,r1,r14
	and r14,r4,#0xf @ rem
	eor r7,r7,r8,lsl#16 @ ^= rem_4bit[rem]
	add r14,r14,r14
	ldmia r11,{r8-r11} @ load Htbl[nhi]
	eor r4,r8,r4,lsr#4
	it pl
	ldrbpl r8,[r0,r3]
	eor r4,r4,r5,lsl#28
	eor r5,r9,r5,lsr#4
	ldrh r9,[sp,r14]
	eor r5,r5,r6,lsl#28
	eor r6,r10,r6,lsr#4
	eor r6,r6,r7,lsl#28
	it pl
	eorpl r12,r12,r8
	eor r7,r11,r7,lsr#4
	itt pl
	andpl r14,r12,#0xf0
	andpl r12,r12,#0x0f
	eor r7,r7,r9,lsl#16 @ ^= rem_4bit[rem]
	bpl .Lghash_inner
	ldr r3,[sp,#32] @ re-load r3/end
	add r2,r2,#16
	mov r14,r4
	rev r4,r4
	str r4,[r0,#12]
	cmp r2,r3
	rev r5,r5
	str r5,[r0,#8]
	it ne
	ldrbne r12,[r2,#15]
	rev r6,r6
	str r6,[r0,#4]
	rev r7,r7
	str r7,[r0,#0]
	bne .Lghash_outer
	add sp,sp,#36
	ldmia sp!,{r4-r11,pc}
.size gcm_ghash_4bit, .-gcm_ghash_4bit

.align 2
.thumb_func
.global gcm_gmult_4bit
.type gcm_gmult_4bit, %function
gcm_gmult_4bit:
	stmdb sp!,{r4-r11,lr}
	ldrb r12,[r0,#15]
	adr	r2, rem_4bit
.Lghash_rem_4bit_got:
	and r14,r12,#0xf0
	and r12,r12,#0x0f
	mov r3,#14
	add r7,r1,r12,lsl#4
	ldmia r7,{r4-r7} @ load Htbl[nlo]
	ldrb r12,[r0,#14]
	add r11,r1,r14
	and r14,r4,#0xf @ rem
	ldmia r11,{r8-r11} @ load Htbl[nhi]
	add r14,r14,r14
	eor r4,r8,r4,lsr#4
	ldrh r8,[r2,r14] @ rem_4bit[rem]
	eor r4,r4,r5,lsl#28
	eor r5,r9,r5,lsr#4
	eor r5,r5,r6,lsl#28
	eor r6,r10,r6,lsr#4
	eor r6,r6,r7,lsl#28
	eor r7,r11,r7,lsr#4
	and r14,r12,#0xf0
	eor r7,r7,r8,lsl#16
	and r12,r12,#0x0f
.Lghash_gmult_loop:
	add r11,r1,r12,lsl#4
	and r12,r4,#0xf @ rem
	subs r3,r3,#1
	add r12,r12,r12
	ldmia r11,{r8-r11} @ load Htbl[nlo]
	eor r4,r8,r4,lsr#4
	eor r4,r4,r5,lsl#28
	eor r5,r9,r5,lsr#4
	eor r5,r5,r6,lsl#28
	ldrh r8,[r2,r12] @ rem_4bit[rem]
	eor r6,r10,r6,lsr#4
	it pl
	ldrbpl r12,[r0,r3]
	eor r6,r6,r7,lsl#28
	eor r7,r11,r7,lsr#4
	add r11,r1,r14
	and r14,r4,#0xf @ rem
	eor r7,r7,r8,lsl#16 @ ^= rem_4bit[rem]
	add r14,r14,r14
	ldmia r11,{r8-r11} @ load Htbl[nhi]
	eor r4,r8,r4,lsr#4
	eor r4,r4,r5,lsl#28
	eor r5,r9,r5,lsr#4
	ldrh r8,[r2,r14] @ rem_4bit[rem]
	eor r5,r5,r6,lsl#28
	eor r6,r10,r6,lsr#4
	eor r6,r6,r7,lsl#28
	eor r7,r11,r7,lsr#4
	itt pl
	andpl r14,r12,#0xf0
	andpl r12,r12,#0x0f
	eor r7,r7,r8,lsl#16 @ ^= rem_4bit[rem]
	bpl .Lghash_gmult_loop
	rev r4,r4
	str r4,[r0,#12]
	rev r5,r5
	str r5,[r0,#8]
	rev r6,r6
	str r6,[r0,#4]
	rev r7,r7
	str r7,[r0,#0]
	ldmia sp!,{r4-r11,pc}
.size gcm_gmult_4bit, .-gcm_gmult_4bit

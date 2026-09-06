.syntax unified
.thumb
.text

.align 5
K512:
	.word	0xd728ae22, 0x428a2f98, 0x23ef65cd, 0x71374491
	.word	0xec4d3b2f, 0xb5c0fbcf, 0x8189dbbc, 0xe9b5dba5
	.word	0xf348b538, 0x3956c25b, 0xb605d019, 0x59f111f1
	.word	0xaf194f9b, 0x923f82a4, 0xda6d8118, 0xab1c5ed5
	.word	0xa3030242, 0xd807aa98, 0x45706fbe, 0x12835b01
	.word	0x4ee4b28c, 0x243185be, 0xd5ffb4e2, 0x550c7dc3
	.word	0xf27b896f, 0x72be5d74, 0x3b1696b1, 0x80deb1fe
	.word	0x25c71235, 0x9bdc06a7, 0xcf692694, 0xc19bf174
	.word	0x9ef14ad2, 0xe49b69c1, 0x384f25e3, 0xefbe4786
	.word	0x8b8cd5b5, 0x0fc19dc6, 0x77ac9c65, 0x240ca1cc
	.word	0x592b0275, 0x2de92c6f, 0x6ea6e483, 0x4a7484aa
	.word	0xbd41fbd4, 0x5cb0a9dc, 0x831153b5, 0x76f988da
	.word	0xee66dfab, 0x983e5152, 0x2db43210, 0xa831c66d
	.word	0x98fb213f, 0xb00327c8, 0xbeef0ee4, 0xbf597fc7
	.word	0x3da88fc2, 0xc6e00bf3, 0x930aa725, 0xd5a79147
	.word	0xe003826f, 0x06ca6351, 0x0a0e6e70, 0x14292967
	.word	0x46d22ffc, 0x27b70a85, 0x5c26c926, 0x2e1b2138
	.word	0x5ac42aed, 0x4d2c6dfc, 0x9d95b3df, 0x53380d13
	.word	0x8baf63de, 0x650a7354, 0x3c77b2a8, 0x766a0abb
	.word	0x47edaee6, 0x81c2c92e, 0x1482353b, 0x92722c85
	.word	0x4cf10364, 0xa2bfe8a1, 0xbc423001, 0xa81a664b
	.word	0xd0f89791, 0xc24b8b70, 0x0654be30, 0xc76c51a3
	.word	0xd6ef5218, 0xd192e819, 0x5565a910, 0xd6990624
	.word	0x5771202a, 0xf40e3585, 0x32bbd1b8, 0x106aa070
	.word	0xb8d2d0c8, 0x19a4c116, 0x5141ab53, 0x1e376c08
	.word	0xdf8eeb99, 0x2748774c, 0xe19b48a8, 0x34b0bcb5
	.word	0xc5c95a63, 0x391c0cb3, 0xe3418acb, 0x4ed8aa4a
	.word	0x7763e373, 0x5b9cca4f, 0xd6b2b8a3, 0x682e6ff3
	.word	0x5defb2fc, 0x748f82ee, 0x43172f60, 0x78a5636f
	.word	0xa1f0ab72, 0x84c87814, 0x1a6439ec, 0x8cc70208
	.word	0x23631e28, 0x90befffa, 0xde82bde9, 0xa4506ceb
	.word	0xb2c67915, 0xbef9a3f7, 0xe372532b, 0xc67178f2
	.word	0xea26619c, 0xca273ece, 0x21c0c207, 0xd186b8c7
	.word	0xcde0eb1e, 0xeada7dd6, 0xee6ed178, 0xf57d4f7f
	.word	0x72176fba, 0x06f067aa, 0xa2c898a6, 0x0a637dc5
	.word	0xbef90dae, 0x113f9804, 0x131c471b, 0x1b710b35
	.word	0x23047d84, 0x28db77f5, 0x40c72493, 0x32caab7b
	.word	0x15c9bebc, 0x3c9ebe0a, 0x9c100d4c, 0x431d67c4
	.word	0xcb3e42b6, 0x4cc5d4be, 0xfc657e2a, 0x597f299c
	.word	0x3ad6faec, 0x5fcb6fab, 0x4a475817, 0x6c44198c
.size K512, .-K512

.align 2
.thumb_func
.global sha512_block_data_order
.type sha512_block_data_order, %function
sha512_block_data_order:
	add	r2, r1, r2, lsl #7
	stmdb	sp!, {r4-r12, lr}
	ldr	r14, =K512
	sub	sp,sp,#9*8

	ldr	r7,[r0,#32+0]
	ldr	r8,[r0,#32+4]
	ldr	r9, [r0,#48+0]
	ldr	r10, [r0,#48+4]
	ldr	r11, [r0,#56+0]
	ldr	r12, [r0,#56+4]
.Loop:
	str	r9, [sp,#48+0]
	str	r10, [sp,#48+4]
	str	r11, [sp,#56+0]
	str	r12, [sp,#56+4]
	ldr	r5,[r0,#0+0]
	ldr	r6,[r0,#0+4]
	ldr	r3,[r0,#8+0]
	ldr	r4,[r0,#8+4]
	ldr	r9, [r0,#16+0]
	ldr	r10, [r0,#16+4]
	ldr	r11, [r0,#24+0]
	ldr	r12, [r0,#24+4]
	str	r3,[sp,#8+0]
	str	r4,[sp,#8+4]
	str	r9, [sp,#16+0]
	str	r10, [sp,#16+4]
	str	r11, [sp,#24+0]
	str	r12, [sp,#24+4]
	ldr	r3,[r0,#40+0]
	ldr	r4,[r0,#40+4]
	str	r3,[sp,#40+0]
	str	r4,[sp,#40+4]

.L00_15:
	ldr	r3,[r1,#4]
	ldr	r4,[r1],#8
	rev	r3,r3
	rev	r4,r4
	@ Sigma1(x)	(ROTR((x),14) ^ ROTR((x),18)  ^ ROTR((x),41))
	@ 0		lo>>14^hi<<18 ^ lo>>18^hi<<14 ^ hi>>9^lo<<23
	@ 4		hi>>14^lo<<18 ^ hi>>18^lo<<14 ^ lo>>9^hi<<23
	mov	r9,r7,lsr#14
	str	r3,[sp,#64+0]
	mov	r10,r8,lsr#14
	str	r4,[sp,#64+4]
	eor	r9,r9,r8,lsl#18
	ldr	r11,[sp,#56+0]	@ h.lo
	eor	r10,r10,r7,lsl#18
	ldr	r12,[sp,#56+4]	@ h.hi
	eor	r9,r9,r7,lsr#18
	eor	r10,r10,r8,lsr#18
	eor	r9,r9,r8,lsl#14
	eor	r10,r10,r7,lsl#14
	eor	r9,r9,r8,lsr#9
	eor	r10,r10,r7,lsr#9
	eor	r9,r9,r7,lsl#23
	eor	r10,r10,r8,lsl#23	@ Sigma1(e)
	adds	r3,r3,r9
	ldr	r9,[sp,#40+0]	@ f.lo
	adc	r4,r4,r10		@ T += Sigma1(e)
	ldr	r10,[sp,#40+4]	@ f.hi
	adds	r3,r3,r11
	ldr	r11,[sp,#48+0]	@ g.lo
	adc	r4,r4,r12		@ T += h
	ldr	r12,[sp,#48+4]	@ g.hi

	eor	r9,r9,r11
	str	r7,[sp,#32+0]
	eor	r10,r10,r12
	str	r8,[sp,#32+4]
	and	r9,r9,r7
	str	r5,[sp,#0+0]
	and	r10,r10,r8
	str	r6,[sp,#0+4]
	eor	r9,r9,r11
	ldr	r11,[r14,#0]	@ K[i].lo
	eor	r10,r10,r12		@ Ch(e,f,g)
	ldr	r12,[r14,#4]	@ K[i].hi

	adds	r3,r3,r9
	ldr	r7,[sp,#24+0]	@ d.lo
	adc	r4,r4,r10		@ T += Ch(e,f,g)
	ldr	r8,[sp,#24+4]	@ d.hi
	adds	r3,r3,r11
	and	r9,r11,#0xff
	adc	r4,r4,r12		@ T += K[i]
	adds	r7,r7,r3
	ldr	r11,[sp,#8+0]	@ b.lo
	adc	r8,r8,r4		@ d += T
	teq	r9,#148

	ldr	r12,[sp,#16+0]	@ c.lo
	it	eq			@ Thumb2 thing, sanity check in ARM
	orreq	r14,r14,#1
	@ Sigma0(x)	(ROTR((x),28) ^ ROTR((x),34) ^ ROTR((x),39))
	@ 0		lo>>28^hi<<4  ^ hi>>2^lo<<30 ^ hi>>7^lo<<25
	@ 4		hi>>28^lo<<4  ^ lo>>2^hi<<30 ^ lo>>7^hi<<25
	mov	r9,r5,lsr#28
	mov	r10,r6,lsr#28
	eor	r9,r9,r6,lsl#4
	eor	r10,r10,r5,lsl#4
	eor	r9,r9,r6,lsr#2
	eor	r10,r10,r5,lsr#2
	eor	r9,r9,r5,lsl#30
	eor	r10,r10,r6,lsl#30
	eor	r9,r9,r6,lsr#7
	eor	r10,r10,r5,lsr#7
	eor	r9,r9,r5,lsl#25
	eor	r10,r10,r6,lsl#25	@ Sigma0(a)
	adds	r3,r3,r9
	and	r9,r5,r11
	adc	r4,r4,r10		@ T += Sigma0(a)

	ldr	r10,[sp,#8+4]	@ b.hi
	orr	r5,r5,r11
	ldr	r11,[sp,#16+4]	@ c.hi
	and	r5,r5,r12
	and	r12,r6,r10
	orr	r6,r6,r10
	orr	r5,r5,r9		@ Maj(a,b,c).lo
	and	r6,r6,r11
	adds	r5,r5,r3
	orr	r6,r6,r12		@ Maj(a,b,c).hi
	sub	sp,sp,#8
	adc	r6,r6,r4		@ h += T
	tst	r14,#1
	add	r14,r14,#8
	tst	r14,#1
	beq	.L00_15
	ldr	r9,[sp,#184+0]
	ldr	r10,[sp,#184+4]
	bic	r14,r14,#1
.L16_79:
	@ sigma0(x)	(ROTR((x),1)  ^ ROTR((x),8)  ^ ((x)>>7))
	@ 0		lo>>1^hi<<31  ^ lo>>8^hi<<24 ^ lo>>7^hi<<25
	@ 4		hi>>1^lo<<31  ^ hi>>8^lo<<24 ^ hi>>7
	mov	r3,r9,lsr#1
	ldr	r11,[sp,#80+0]
	mov	r4,r10,lsr#1
	ldr	r12,[sp,#80+4]
	eor	r3,r3,r10,lsl#31
	eor	r4,r4,r9,lsl#31
	eor	r3,r3,r9,lsr#8
	eor	r4,r4,r10,lsr#8
	eor	r3,r3,r10,lsl#24
	eor	r4,r4,r9,lsl#24
	eor	r3,r3,r9,lsr#7
	eor	r4,r4,r10,lsr#7
	eor	r3,r3,r10,lsl#25

	@ sigma1(x)	(ROTR((x),19) ^ ROTR((x),61) ^ ((x)>>6))
	@ 0		lo>>19^hi<<13 ^ hi>>29^lo<<3 ^ lo>>6^hi<<26
	@ 4		hi>>19^lo<<13 ^ lo>>29^hi<<3 ^ hi>>6
	mov	r9,r11,lsr#19
	mov	r10,r12,lsr#19
	eor	r9,r9,r12,lsl#13
	eor	r10,r10,r11,lsl#13
	eor	r9,r9,r12,lsr#29
	eor	r10,r10,r11,lsr#29
	eor	r9,r9,r11,lsl#3
	eor	r10,r10,r12,lsl#3
	eor	r9,r9,r11,lsr#6
	eor	r10,r10,r12,lsr#6
	ldr	r11,[sp,#120+0]
	eor	r9,r9,r12,lsl#26

	ldr	r12,[sp,#120+4]
	adds	r3,r3,r9
	ldr	r9,[sp,#192+0]
	adc	r4,r4,r10

	ldr	r10,[sp,#192+4]
	adds	r3,r3,r11
	adc	r4,r4,r12
	adds	r3,r3,r9
	adc	r4,r4,r10
	@ Sigma1(x)	(ROTR((x),14) ^ ROTR((x),18)  ^ ROTR((x),41))
	@ 0		lo>>14^hi<<18 ^ lo>>18^hi<<14 ^ hi>>9^lo<<23
	@ 4		hi>>14^lo<<18 ^ hi>>18^lo<<14 ^ lo>>9^hi<<23
	mov	r9,r7,lsr#14
	str	r3,[sp,#64+0]
	mov	r10,r8,lsr#14
	str	r4,[sp,#64+4]
	eor	r9,r9,r8,lsl#18
	ldr	r11,[sp,#56+0]	@ h.lo
	eor	r10,r10,r7,lsl#18
	ldr	r12,[sp,#56+4]	@ h.hi
	eor	r9,r9,r7,lsr#18
	eor	r10,r10,r8,lsr#18
	eor	r9,r9,r8,lsl#14
	eor	r10,r10,r7,lsl#14
	eor	r9,r9,r8,lsr#9
	eor	r10,r10,r7,lsr#9
	eor	r9,r9,r7,lsl#23
	eor	r10,r10,r8,lsl#23	@ Sigma1(e)
	adds	r3,r3,r9
	ldr	r9,[sp,#40+0]	@ f.lo
	adc	r4,r4,r10		@ T += Sigma1(e)
	ldr	r10,[sp,#40+4]	@ f.hi
	adds	r3,r3,r11
	ldr	r11,[sp,#48+0]	@ g.lo
	adc	r4,r4,r12		@ T += h
	ldr	r12,[sp,#48+4]	@ g.hi

	eor	r9,r9,r11
	str	r7,[sp,#32+0]
	eor	r10,r10,r12
	str	r8,[sp,#32+4]
	and	r9,r9,r7
	str	r5,[sp,#0+0]
	and	r10,r10,r8
	str	r6,[sp,#0+4]
	eor	r9,r9,r11
	ldr	r11,[r14,#0]	@ K[i].lo
	eor	r10,r10,r12		@ Ch(e,f,g)
	ldr	r12,[r14,#4]	@ K[i].hi

	adds	r3,r3,r9
	ldr	r7,[sp,#24+0]	@ d.lo
	adc	r4,r4,r10		@ T += Ch(e,f,g)
	ldr	r8,[sp,#24+4]	@ d.hi
	adds	r3,r3,r11
	and	r9,r11,#0xff
	adc	r4,r4,r12		@ T += K[i]
	adds	r7,r7,r3
	ldr	r11,[sp,#8+0]	@ b.lo
	adc	r8,r8,r4		@ d += T
	teq	r9,#23

	ldr	r12,[sp,#16+0]	@ c.lo
	it	eq			@ Thumb2 thing, sanity check in ARM
	orreq	r14,r14,#1
	@ Sigma0(x)	(ROTR((x),28) ^ ROTR((x),34) ^ ROTR((x),39))
	@ 0		lo>>28^hi<<4  ^ hi>>2^lo<<30 ^ hi>>7^lo<<25
	@ 4		hi>>28^lo<<4  ^ lo>>2^hi<<30 ^ lo>>7^hi<<25
	mov	r9,r5,lsr#28
	mov	r10,r6,lsr#28
	eor	r9,r9,r6,lsl#4
	eor	r10,r10,r5,lsl#4
	eor	r9,r9,r6,lsr#2
	eor	r10,r10,r5,lsr#2
	eor	r9,r9,r5,lsl#30
	eor	r10,r10,r6,lsl#30
	eor	r9,r9,r6,lsr#7
	eor	r10,r10,r5,lsr#7
	eor	r9,r9,r5,lsl#25
	eor	r10,r10,r6,lsl#25	@ Sigma0(a)
	adds	r3,r3,r9
	and	r9,r5,r11
	adc	r4,r4,r10		@ T += Sigma0(a)

	ldr	r10,[sp,#8+4]	@ b.hi
	orr	r5,r5,r11
	ldr	r11,[sp,#16+4]	@ c.hi
	and	r5,r5,r12
	and	r12,r6,r10
	orr	r6,r6,r10
	orr	r5,r5,r9		@ Maj(a,b,c).lo
	and	r6,r6,r11
	adds	r5,r5,r3
	orr	r6,r6,r12		@ Maj(a,b,c).hi
	sub	sp,sp,#8
	adc	r6,r6,r4		@ h += T
	tst	r14,#1
	add	r14,r14,#8
	ittt	eq			@ Thumb2 thing, sanity check in ARM
	ldreq	r9,[sp,#184+0]
	ldreq	r10,[sp,#184+4]
	beq	.L16_79
	bic	r14,r14,#1

	ldr	r3,[sp,#8+0]
	ldr	r4,[sp,#8+4]
	ldr	r9, [r0,#0+0]
	ldr	r10, [r0,#0+4]
	ldr	r11, [r0,#8+0]
	ldr	r12, [r0,#8+4]
	adds	r9,r5,r9
	str	r9, [r0,#0+0]
	adc	r10,r6,r10
	str	r10, [r0,#0+4]
	adds	r11,r3,r11
	str	r11, [r0,#8+0]
	adc	r12,r4,r12
	str	r12, [r0,#8+4]

	ldr	r5,[sp,#16+0]
	ldr	r6,[sp,#16+4]
	ldr	r3,[sp,#24+0]
	ldr	r4,[sp,#24+4]
	ldr	r9, [r0,#16+0]
	ldr	r10, [r0,#16+4]
	ldr	r11, [r0,#24+0]
	ldr	r12, [r0,#24+4]
	adds	r9,r5,r9
	str	r9, [r0,#16+0]
	adc	r10,r6,r10
	str	r10, [r0,#16+4]
	adds	r11,r3,r11
	str	r11, [r0,#24+0]
	adc	r12,r4,r12
	str	r12, [r0,#24+4]

	ldr	r3,[sp,#40+0]
	ldr	r4,[sp,#40+4]
	ldr	r9, [r0,#32+0]
	ldr	r10, [r0,#32+4]
	ldr	r11, [r0,#40+0]
	ldr	r12, [r0,#40+4]
	adds	r7,r7,r9
	str	r7,[r0,#32+0]
	adc	r8,r8,r10
	str	r8,[r0,#32+4]
	adds	r11,r3,r11
	str	r11, [r0,#40+0]
	adc	r12,r4,r12
	str	r12, [r0,#40+4]

	ldr	r5,[sp,#48+0]
	ldr	r6,[sp,#48+4]
	ldr	r3,[sp,#56+0]
	ldr	r4,[sp,#56+4]
	ldr	r9, [r0,#48+0]
	ldr	r10, [r0,#48+4]
	ldr	r11, [r0,#56+0]
	ldr	r12, [r0,#56+4]
	adds	r9,r5,r9
	str	r9, [r0,#48+0]
	adc	r10,r6,r10
	str	r10, [r0,#48+4]
	adds	r11,r3,r11
	str	r11, [r0,#56+0]
	adc	r12,r4,r12
	str	r12, [r0,#56+4]

	add	sp,sp,#640
	sub	r14,r14,#640

	teq	r1,r2
	bne	.Loop

	add	sp,sp,#8*9		@ destroy frame
ldmia	sp!, {r4-r12, pc}
.size	sha512_block_data_order,.-sha512_block_data_order

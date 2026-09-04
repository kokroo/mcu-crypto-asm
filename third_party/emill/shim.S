@ AAPCS wrapper around Emill's internal P256_mulmod, for benchmarking.
@ Concatenated onto a copy of p256-cortex-m4-asm-gcc.S by harness/build.rs:
@ `.global` only works in the assembly unit that defines the symbol.

	.syntax unified
	.thumb
	.text
	.global emill_p256_mulmod
	.p2align 2
	.thumb_func
	.type emill_p256_mulmod, %function
@ void emill_p256_mulmod(uint32_t out[8], const uint32_t a[8], const uint32_t b[8]);
emill_p256_mulmod:
	@ 10 registers = 40 bytes, so the stack stays 8-byte aligned, and r0
	@ (the out pointer) is stashed at [sp] because P256_mulmod clobbers r12.
	push	{r0, r4-r11, lr}
	@ r1 and r2 are already the operand pointers Emill's routine expects.
	p256_mulmod_core 1		@ result comes back in r0-r7, out pointer pre-loaded into lr
	stm	lr, {r0-r7}
	pop	{r0, r4-r11, pc}
	.size	emill_p256_mulmod, .-emill_p256_mulmod

# ESP32-S3 bare-metal entry, CALL0 ABI.
#
# The windowed ABI needs PS.WOE=1, and enabling it here raises an immediate
# window exception that vectors to ROM (VECBASE still points there and we have
# no handlers) -- single-stepping showed `wsr.ps` jumping straight to
# 0x400003c0. call0 sidesteps register windows entirely, which is what a
# handler-less harness wants. The arithmetic body of the assembly is identical
# either way; only the prologue/epilogue differ.
	.section .entry, "ax"
	.global _start
	.align 4
_start:
	movi	a1, _stack_top
	call0	xmain
1:	j	1b

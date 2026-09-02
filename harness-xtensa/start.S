# Minimal ESP32-S3 bare-metal entry for the QEMU correctness harness.
# Sets up the windowed ABI (PS.WOE + WindowBase/WindowStart) before calling
# into C -- without this a windowed call silently does nothing.
	.section .entry, "ax"
	.global _start
	.align 4
_start:
	movi	a2, 0
	wsr.windowbase	a2
	rsync
	movi	a2, 1
	wsr.windowstart	a2
	rsync
	movi	a2, 0x40020		# PS: WOE=1, UM=1, INTLEVEL=0
	wsr.ps	a2
	rsync
	movi	a1, _stack_top
	movi	a0, 0
	call4	xmain
1:	j	1b

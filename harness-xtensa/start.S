# Minimal ESP32-S3 bare-metal entry for the on-target harness.
#
# Run after `reset halt`, so WindowBase/WindowStart are already at their reset
# values and consistent. Writing WINDOWBASE here would remap the register file
# mid-sequence -- it is both unnecessary from a clean reset and a good way to
# halt three instructions in.
#
# PS.WOE must be set or windowed calls (which is what Rust and GCC emit on
# Xtensa) silently do nothing.
	.section .entry, "ax"
	.global _start
	.align 4
_start:
	movi	a2, 0x40020		# PS: WOE=1, UM=1, INTLEVEL=0
	wsr.ps	a2
	rsync
	movi	a1, _stack_top
	movi	a0, 0
	call4	xmain
1:	j	1b

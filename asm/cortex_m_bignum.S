.syntax unified
.thumb
.arch armv7e-m
       
    .syntax unified
    .text
    .eabi_attribute Tag_ABI_align_preserved, 1
    .cfi_sections .debug_frame
    .thumb
    .balign 4



.thumb_func ; .type mulacc_inner, %function ;mulacc_inner: ; .cfi_startproc
    movs r7,#0
    mov r8,r7
    umull r9,r10,r7,r7
mulacc_inner_with_carry:
    push {lr}
    .cfi_def_cfa_offset 4
    .cfi_offset lr,-4

    ldr r12,[r4],#4
    ldr lr,[r5]
    b 1f

0:
mulacc_inner1:
    ldr r12,[r4],#4
    ldr lr,[r5,#4]
    str.w r11,[r5],#4
1:
    umaal lr,r7,r12,r0 ; umaal r7,r8,r12,r1 ; umaal r8,r9,r12,r2 ; umaal r9,r10,r12,r3 ; ldr r12,[r4],#4 ; ldr r11,[r5,#4] ; str.w lr,[r5],#4
    umaal r11,r7,r12,r0 ; umaal r7,r8,r12,r1 ; umaal r8,r9,r12,r2 ; umaal r9,r10,r12,r3 ; ldr r12,[r4],#4 ; ldr lr,[r5,#4] ; str.w r11,[r5],#4
    umaal lr,r7,r12,r0 ; umaal r7,r8,r12,r1 ; umaal r8,r9,r12,r2 ; umaal r9,r10,r12,r3 ; ldr r12,[r4],#4 ; ldr r11,[r5,#4] ; str.w lr,[r5],#4

    umaal r11,r7,r12,r0 ; umaal r7,r8,r12,r1 ; umaal r8,r9,r12,r2 ; umaal r9,r10,r12,r3
mulacc_inner2:
    ldr r12,[r4],#4
    ldr lr,[r5,#4]
    str.w r11,[r5],#4

    umaal lr,r7,r12,r0 ; umaal r7,r8,r12,r1 ; umaal r8,r9,r12,r2 ; umaal r9,r10,r12,r3 ; ldr r12,[r4],#4 ; ldr r11,[r5,#4] ; str.w lr,[r5],#4
    umaal r11,r7,r12,r0 ; umaal r7,r8,r12,r1 ; umaal r8,r9,r12,r2 ; umaal r9,r10,r12,r3 ; ldr r12,[r4],#4 ; ldr lr,[r5,#4] ; str.w r11,[r5],#4
    umaal lr,r7,r12,r0 ; umaal r7,r8,r12,r1 ; umaal r8,r9,r12,r2 ; umaal r9,r10,r12,r3 ; ldr r12,[r4],#4 ; ldr r11,[r5,#4] ; str.w lr,[r5],#4
    umaal r11,r7,r12,r0 ; umaal r7,r8,r12,r1 ; umaal r8,r9,r12,r2 ; umaal r9,r10,r12,r3
    subs r6,r6,#32
    bhi 0b

    ldr lr,[sp],#4
    .cfi_def_cfa_offset 0
    .cfi_restore lr
    str r11,[r5],#4
    bx lr
.cfi_endproc ; .size mulacc_inner, .-mulacc_inner



.global bignum_mulacc ; .thumb_func ; .type bignum_mulacc, %function ;bignum_mulacc: ; .cfi_startproc
    add r12,r1,r3
    push {r3-r12,lr}
    .cfi_def_cfa_offset 44
    .cfi_offset r4,-40
    .cfi_offset r5,-36
    .cfi_offset r6,-32
    .cfi_offset r7,-28
    .cfi_offset r8,-24
    .cfi_offset r9,-20
    .cfi_offset r10,-16
    .cfi_offset r11,-12
    .cfi_offset lr,-4

    mov r4,r2
    mov r6,r3
    mov r7,r1
    mov r5,r0
    ldm r7!,{r0-r3}
    push {r7}
    .cfi_def_cfa_offset 48
    bl mulacc_inner

1:
    stm r5!,{r7-r10}
    ldr r7,[sp]
    ldr r6,[sp,#4*10]
    ldm r7!,{r0-r3}
    cmp r6,r7
    it eq
    addeq lr,lr,2f-1b
    ldr r6,[sp,#4*1]
    str r7,[sp]
    subs r5,r5,r6
    subs r4,r4,r6
    b mulacc_inner

2:
    stm r5!,{r7-r10}

    pop {r2-r12,pc}
.cfi_endproc ; .size bignum_mulacc, .-bignum_mulacc


.global bignum_sqracc ; .thumb_func ; .type bignum_sqracc, %function ;bignum_sqracc: ; .cfi_startproc
    movs r3,#0
    push {r2-r11,lr}
    .cfi_def_cfa_offset 44
    .cfi_offset r4,-36
    .cfi_offset r5,-32
    .cfi_offset r6,-28
    .cfi_offset r7,-24
    .cfi_offset r8,-20
    .cfi_offset r9,-16
    .cfi_offset r10,-12
    .cfi_offset r11,-8
    .cfi_offset lr,-4
    mov r4,r1
    mov r5,r0
    bl 0f


    stm r5!,{r7-r10}
    ldr r6,[sp]
    subs r5,r5,r6
    subs r4,r4,r6

0:
    ldr r7,[sp,#4]
    ldr r6,[r5]
    lsrs r0,r7,#1
    ldm r4!,{r0-r3}
    muls r7,r0,r7
    umaal r6,r7,r0,r0

    and r8,r1,r0, asr #31
    adcs r0,r0,r0

    ldr r11,[r5,#4]
    str r6,[r5],#4

    umaal r11,r7,r1,r0
    umaal r7,r8,r1,r1

    and r9,r2,r1, asr #31
    adcs r1,r1,r1

    ldr r6,[r5,#4]
    str r11,[r5],#4

    umaal r6,r7,r2,r0
    umaal r7,r8,r2,r1
    umaal r8,r9,r2,r2

    and r10,r3,r2, asr #31
    adcs r2,r2,r2

    ldr r11,[r5,#4]
    str r6,[r5],#4

    umaal r11,r7,r3,r0
    umaal r7,r8,r3,r1
    umaal r8,r9,r3,r2
    umaal r9,r10,r3,r3

    adcs r3,r3,r3
    movs r6,#0
    adcs r6,r6,r6
    str r6,[sp,#4]

    ldr r6,[sp]
    subs r6,r6,#16
    str r6,[sp]
    beq 0f
    lsls r12,r6,#27
    push {lr}
    .cfi_def_cfa_offset 48
    bmi mulacc_inner2
    b mulacc_inner1

0:
    .cfi_def_cfa_offset 44
    mov r6,r11
    stm r5!,{r6-r10}
    pop {r1,r2,r4-r11,pc}
.cfi_endproc ; .size bignum_sqracc, .-bignum_sqracc
.global bignum_mont_redc ; .thumb_func ; .type bignum_mont_redc, %function ;bignum_mont_redc: ; .cfi_startproc
    push {r1-r11,lr}
    .cfi_def_cfa_offset 48
    .cfi_offset r4,-36
    .cfi_offset r5,-32
    .cfi_offset r6,-28
    .cfi_offset r7,-24
    .cfi_offset r8,-20
    .cfi_offset r9,-16
    .cfi_offset r10,-12
    .cfi_offset r11,-8
    .cfi_offset lr,-4

    mov r5,r0
    movs r4,#0
    add r0,r5,r1
    push {r0,r4}
    .cfi_def_cfa_offset 56

0:
    ldr r7,[sp,#4*4]
    ldm r7,{r4,r6,r12,lr}
    ldm r5,{r8-r11}
    umull r0,r1,r4,r8
    umull r2,r3,r4,r9
    umaal r1,r2,r6,r8
    umaal r2,r3,r4,r10
    umull r4,r11,r4,r11
    umull r7,r11,r6,r9
    umaal r3,r4,r6,r10
    umaal r2,r7,r12,r8
    umaal r3,r11,r12,r9
    umaal r3,r7,lr,r8
    ldr r4,[sp,#4*3]
    ldr r6,[sp,#4*2]
    bl mulacc_inner

    ldr r0,[sp,#4*1]
    ldm r5,{r1-r4}
    movs r6,#1
    umaal r1,r0,r6,r7
    umaal r2,r0,r6,r8
    umaal r3,r0,r6,r9
    umaal r4,r0,r6,r10
    stm r5!,{r1-r4}
    ldr r6,[sp,#4*2]
    ldr r7,[sp]
    str r0,[sp,#4*1]
    subs r5,r5,r6
    cmp r5,r7
    bne 0b

    ldr r1,[sp,#4*14]
    ldr lr,[sp,#4*15]
    mov r11,r0
    cmp r12,#0
    blt 1f

.L_reduce_once:



    movs r0,#1
    mov r11,r0
0:
    ldm r7!,{r2-r5}
    ldm r1!,{r8-r10,r12}
    umaal r2,r11,r0,r8
    umaal r3,r11,r0,r9
    umaal r4,r11,r0,r10
    umaal r5,r11,r0,r12
    stm lr!,{r2-r5}
    subs r6,r6,#16
    bne 0b
    ldr r2,[sp,#4*1]
    add r2,r2,r11
    eors r0,r0,r2
    mov r11,r6
    ldr r6,[sp,#4*2]
    ldr r1,[sp,#4*3]
    sub lr,lr,r6
    mov r7,lr
1:
    ldm r7!,{r2-r5}
    ldm r1!,{r8-r10,r12}
    umaal r2,r11,r0,r8
    umaal r3,r11,r0,r9
    umaal r4,r11,r0,r10
    umaal r5,r11,r0,r12
    stm lr!,{r2-r5}
    subs r6,r6,#16
    bne 1b

    add sp,sp,#20
    .cfi_def_cfa_offset 36
    pop {r4-r11,pc}
.cfi_endproc ; .size bignum_mont_redc, .-bignum_mont_redc
.global bignum_to_mont ; .thumb_func ; .type bignum_to_mont, %function ;bignum_to_mont: ; .cfi_startproc
    push {r0,r2-r11,lr}
    .cfi_def_cfa_offset 48
    .cfi_offset r4,-36
    .cfi_offset r5,-32
    .cfi_offset r6,-28
    .cfi_offset r7,-24
    .cfi_offset r8,-20
    .cfi_offset r9,-16
    .cfi_offset r10,-12
    .cfi_offset r11,-8
    .cfi_offset lr,-4
    sub sp,sp,#16
    .cfi_def_cfa_offset 64

    add r6,r0,r2, lsl #1
    str r6,[sp,#12]

    add r9,r1,r2
    ldr r8,[r9,#-4]!
    cmp r8,#0
    blt 0f

    sub r0,r6,#4
    add r3,r3,r2
    str r3,[sp]
    add r3,r3,r2

    mov r4,r9

    bne 2f

1:
    ldr r8,[r9,#-4]!
    subs r0,r0,#4
    cmp r8,#0
    beq 1b
2:
    subs r4,r4,r9
    clz r5,r8
    str r4,[sp,#4]
    str r5,[sp,#8]
    rsbs r2,r2,#0


    ldr r7,[r0]
    lsls r7,r7,r5
    movs r10,#1
    lsls r10,r10,r5
    umull r5,r4,r10,r8

    b 4f
5:
    umull r11,r12,r4,r4

    ldr r8,[r9,#-4]!
    ldr lr,[r0,#-4]!

    umlal r12,r5,r10,r8
    str r5,[r3,#-4]!
    mvns r5,r5
    str r5,[r3,r2]
    mov r5,r12

    umlal r11,r7,r10,lr
    str r7,[r6,#-4]!
    mov r7,r11

    str r4,[r6,r2]
4:
    cmp r9,r1
    bne 5b

    str r5,[r3,#-4]!
    mvns r5,r5
    str r5,[r3,r2]
    str r7,[r6,#-4]!
    str r4,[r6,r2]
    mvns r7,r4
    ldr r1,[sp,#24]
    subs r1,r1,r2
    b 7f

6:
    str r4,[r3,#-4]!
    str r7,[r3,r2]
    str r4,[r6,#-4]!
    str r4,[r6,r2]
7:
    cmp r3,r1
    bne 6b
    subs r1,r1,r2
    b 1f

0:
    movs r4,#0
    umull r8,r12,r4,r4
    umull r10,r11,r4,r4
    stm sp,{r1,r4,r8}
0:
    ldm r1!,{r4-r7}
    mvns r4,r4
    mvns r5,r5
    mvns r6,r6
    mvns r7,r7
    stm r3!,{r4-r7}
    stm r0!,{r8,r10-r12}
    cmp r1,r9
    blt 0b

1:



    ldmdb r1,{r0-r4}
    mov lr,#32
    lsrs r7,r0,#27
    umull r6,r5,lr,r2
    lsrs r0,r4,#11
    umull r4,r12,lr,r4
    umlal r7,r6,lr,r1
    umlal r5,r4,lr,r3
    add r1,r12,r12, lsl #3
    movs r2,#24
    sub r1,r2,r1, lsr #4


    lsrs r3,r0,#(25-11)
    muls r3,r1,r3
    lsls r2,r1,#3
    muls r1,r3,r1
    sub r1,r2,r1, lsr #8


    lsrs r3,r0,#(23-11)
    muls r3,r1,r3
    lsls r2,r1,#3
    muls r1,r3,r1
    sub r1,r2,r1, lsr #12


    lsrs r3,r0,#(19-11)
    muls r3,r1,r3
    lsls r2,r1,#5
    muls r1,r3,r1
    sub r1,r2,r1, lsr #16


    umull r2,r8,r1,r1
    umull r3,r2,r2,r0
    lsrs r3,r3,#24
    orr r3,r3,r2, lsl #8
    rsb r3,r3,r1, lsl #9


    umull r1,lr,r3,r4
    mla lr,r3,r12,lr
    umull r10,r11,r1,r3
    umlal r11,r8,lr,r3
    lsrs r11,r11,#4
    orr r11,r11,r8, lsl #28
    lsrs r2,r3,#11
    rsbs r3,r11,r3, lsl #21
    sbc r11,r2,r8, lsr #4


    umull r8,r9,r3,r3
    umull r10,r1,r3,r11
    umaal r9,r10,r3,r11
    umaal r10,r1,r11,r11

    umull r0,lr,r5,r8
    umull r1,r2,r5,r9
    umaal r1,lr,r4,r8
    umull r0,r1,r5,r10
    umaal r0,lr,r4,r9
    umaal r1,lr,r4,r10
    umaal r0,r2,r12,r8
    umaal r1,r2,r12,r9
    umaal r2,lr,r12,r10

    lsrs r0,r0,#13
    orr r0,r0,r1, lsl #19
    lsrs r1,r1,#13
    orr r1,r1,r2, lsl #19

    rsbs r0,r0,#0
    sbcs r3,r3,r1
    sbc r11,r11,r2, lsr #13
    push {r0,r3,r11}
    .cfi_def_cfa_offset 76


    umull r1,r2,r0,r0
    umull r8,r9,r0,r3
    umull r10,lr,r0,r11
    umaal r2,r8,r3,r0
    umaal r8,r9,r3,r3
    umaal r9,lr,r3,r11
    umaal r8,r10,r11,r0
    umaal r9,r10,r11,r3
    umaal r10,lr,r11,r11
    umull r3,r11,r1,r4
    umaal r3,lr,r2,r5
    umaal r11,lr,r1,r12
    umull r0,r1,r8,r6
    umaal r11,r1,r2,r4
    umaal r1,lr,r2,r12
    umaal r0,r3,r9,r7
    umaal r3,r11,r8,r5
    umaal r1,r11,r8,r4
    umaal r11,lr,r8,r12
    umull r0,r2,r9,r6
    umaal r1,r2,r9,r5
    umaal r2,r11,r9,r4
    umaal r11,lr,r9,r12
    umaal r0,r3,r10,r7
    umaal r1,r3,r10,r6
    umaal r2,r3,r10,r5
    umaal r3,r11,r10,r4
    umaal r11,lr,r10,r12


    mov r12,#(1<<(32-12))
    umull r10,r0,r12,r0
    umull r4,r5,r12,r2
    umull r6,r7,r12,r11
    umlal r0,r4,r12,r1
    umlal r5,r6,r12,r3

    rsbs r0,r0,#0
    sbcs r1,lr,r4

    pop {r2-r4}
    .cfi_def_cfa_offset 64
    sbcs r2,r2,r5
    sbcs r3,r3,r6
    sbcs r4,r4,r7
    push {r0-r4}
    .cfi_def_cfa_offset 84



    ldr r5,[sp,#32]
    ldmdb r5!,{r7-r11}
    adds r5,r5,#4
0:
    ldm sp,{r0-r4}
    umull r12,r0,r11,r0
    umull r6,lr,r10,r1
    umaal r0,lr,r11,r1
    umaal r12,r6,r9,r2
    umaal r0,r6,r10,r2
    umaal r6,lr,r11,r2
    umull r1,r2,r8,r3
    umaal r0,r2,r9,r3
    umaal r6,r2,r10,r3
    umaal lr,r2,r11,r3
    umaal r12,r1,r7,r4
    adds r1,r1,#(1<<4)
    umaal r0,r1,r8,r4
    umaal r6,r1,r9,r4
    umaal r1,lr,r10,r4
    umaal lr,r2,r11,r4


    mov r12,#(1<<27)
    lsrs r0,r0,#5
    umull r3,r4,r12,r2
    umull r1,r2,r12,r1
    umlal r0,r1,r12,r6
    umlal r2,r3,r12,lr


    subs r0,r0,r4
    movs r4,#0
    sbcs r1,r1,r4
    sbcs r2,r2,r4
    sbcs r3,r3,r4






    sub r7,r0,r8

    ldr r4,[sp,#44]
    ldr r6,[sp,#40]
    str r7,[sp,#32]
    subs r5,r5,r6
    mov r7,r0
    mov r8,r1
    mov r9,r2
    mov r10,r3
    bl mulacc_inner_with_carry
    ldr r2,[sp,#32]
    ldr r4,[sp,#20]

    ldr r0,[sp,#40]
    sub lr,r2,r7



    subs r5,r5,r0
    mov r12,r5

1:
    ldm r4!,{r1,r2,r3,r7}
    ldm r5,{r8-r11}
    umaal r8,r6,lr,r1
    umaal r9,r6,lr,r2
    umaal r10,r6,lr,r3
    umaal r11,r6,lr,r7
    stm r5!,{r8-r11}
    subs r0,r0,#16
    bne 1b

    subs r5,r5,#20
    ldr r3,[sp,#36]
    ldm r5!,{r7}
    cmp r3,r12
    bne 0b


    ldr r2,[sp,#24]
    ldr r7,[sp,#28]
    adds r6,r2,r7
    cbz r6,1f

    adds r5,r5,#16
    adds r4,r3,r2
0:
    str r0,[r5,r2]
    subs r2,r2,#4
    bpl 0b
    rsb r6,r7,#32
    ldm r4!,{r0}
    lsrs r0,r0,r7
0:
    ldm r4!,{r1}
    lsls r2,r1,r6
    orrs r0,r0,r2
    stm r3!,{r0}
    lsrs r0,r1,r7
    cmp r3,r5
    bne 0b
1:

    add sp,sp,#48
    .cfi_def_cfa_offset 36
    pop {r4-r11,pc}
.cfi_endproc ; .size bignum_to_mont, .-bignum_to_mont



.global bignum_modular_inverse ; .thumb_func ; .type bignum_modular_inverse, %function ;bignum_modular_inverse: ; .cfi_startproc
    push {r4-r11,lr}
    .cfi_def_cfa_offset 36
    .cfi_offset r4,-36
    .cfi_offset r5,-32
    .cfi_offset r6,-28
    .cfi_offset r7,-24
    .cfi_offset r8,-20
    .cfi_offset r9,-16
    .cfi_offset r10,-12
    .cfi_offset r11,-8
    .cfi_offset lr,-4
    ldm r1!,{r2-r5}
    movs r1,#2
    rsbs r7,r2,#0

    mla r6,r2,r7,r1
    muls r6,r7,r6

    mla r7,r2,r6,r1
    muls r7,r6,r7

    mla r6,r2,r7,r1
    muls r6,r7,r6

    mla r7,r2,r6,r1
    muls r7,r6,r7

    mul r8,r3,r7
    umlal r1,r8,r2,r7
    umull r6,r9,r1,r7
    mla r9,r8,r7,r9
    umull r7,r8,r6,r6
    umull r10,r11,r6,r9
    umaal r8,r10,r9,r6
    umaal r10,r11,r9,r9


    mov r1,r6
    mov r12,r9
    umaal r1,r6,r2,r7
    umaal r9,r12,r2,r8
    umaal r6,r9,r3,r7
    umaal r9,r12,r2,r10
    stm r0!,{r1,r6}
    umull r1,r6,r3,r8
    umaal r1,r9,r4,r7
    umaal r6,r12,r2,r11
    umaal r6,r9,r3,r10
    mla r6,r4,r8,r6
    mla r6,r5,r7,r6
    stm r0!,{r1,r6}
    pop {r4-r11,pc}
.cfi_endproc ; .size bignum_modular_inverse, .-bignum_modular_inverse





.global bignum_submod ; .thumb_func ; .type bignum_submod, %function ;bignum_submod: ; .cfi_startproc
    push {r4-r11,lr}
    .cfi_def_cfa_offset 36
    .cfi_offset r4,-36
    .cfi_offset r5,-32
    .cfi_offset r6,-28
    .cfi_offset r7,-24
    .cfi_offset r8,-20
    .cfi_offset r9,-16
    .cfi_offset r10,-12
    .cfi_offset r11,-8
    .cfi_offset lr,-4
    movs r5,#0
    ldr r6,[sp,#4*9]
    mov r7,r2
    push {r4-r7,lr}
    .cfi_def_cfa_offset 56
    mov lr,r0
    mov r7,r3
    b .L_reduce_once
.cfi_endproc ; .size bignum_submod, .-bignum_submod
    .section .note.GNU-stack,"",%progbits

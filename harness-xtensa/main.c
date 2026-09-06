/* On-target correctness harness for the Xtensa LX7 assembly.
 *
 * This is C rather than Rust because LLVM's Xtensa assembler does not
 * implement SALTU, so the assembly must go through the esp GNU toolchain.
 * Runs under Espressif's QEMU fork (`-machine esp32s3`) and on real hardware
 * unchanged.
 *
 * The vectors in kat.h are generated independently by Python bignum, so this
 * pins the assembly to an external oracle rather than to another
 * implementation that could share a bug. */

#include <stdint.h>
#include <stddef.h>
#include "kat.h"

#define UART0_FIFO (*(volatile uint32_t *)0x60000000)

/* Results land at a fixed address so a debugger can read them out: the
 * Heltec-V3 has no USB serial, only a J-Link, so UART output is invisible on
 * real hardware. Under QEMU the UART path still works and both agree. */
#define R_MAGIC 0u
#define R_P256_FAILS 1u
#define R_P384_FAILS 2u
#define R_P256_CYCLES 3u
#define R_P384_CYCLES 4u
#define R_ITERS 5u
#define R_DONE 6u
#define R_FIAT_P256_CYCLES 7u
#define R_FIAT_P384_CYCLES 8u
#define R_CROSSCHECK 9u
#define R_FAILIDX 10u
#define R_GOT 11u
#define R_WANT 12u
#define R_LIMB 13u
#define R_P256_ADD_CYCLES 14u
#define R_P256_SUB_CYCLES 15u
#define R_P384_ADD_CYCLES 16u
#define R_P384_SUB_CYCLES 17u
#define R_ADD_SUB_FAILS 18u
#define R_P256_SQR_CYCLES 19u
#define R_P384_SQR_CYCLES 20u
#define R_SQR_FAILS 21u
volatile uint32_t g_results[32] __attribute__((used, section(".results")));

/* Baseline: fiat-crypto's generated Montgomery multiply -- the same operation,
 * and the code RustCrypto ships. Without this the Xtensa numbers have nothing
 * to be compared against. */
extern void fiat_p256_mul_ext(uint32_t *out, const uint32_t *a, const uint32_t *b);
extern void fiat_p384_mul_ext(uint32_t *out, const uint32_t *a, const uint32_t *b);

/* Xtensa cycle counter. Free-running at the CPU clock; exact, unlike the
 * SysTick fallback QEMU forced on the Cortex-M side. */
static inline uint32_t ccount(void) {
    uint32_t c;
    __asm__ __volatile__("rsr.ccount %0" : "=r"(c));
    return c;
}

/* On real hardware started from `reset halt`, peripheral clocks are off and
 * touching the UART registers bus-faults. The results block is the only output
 * that works there; under QEMU the UART is live and both agree. */
#ifdef NO_UART
static void putc_(char c) { (void)c; }
#else
static void putc_(char c) { UART0_FIFO = (uint32_t)(unsigned char)c; }
#endif
static void puts_(const char *s) { while (*s) putc_(*s++); }
static void putu_(uint32_t v) {
    char b[12];
    int i = 0;
    if (!v) { putc_('0'); return; }
    while (v) { b[i++] = (char)('0' + v % 10); v /= 10; }
    while (i) putc_(b[--i]);
}
static void puthex_(uint32_t v) {
    const char *h = "0123456789abcdef";
    for (int i = 7; i >= 0; i--) putc_(h[(v >> (i * 4)) & 0xf]);
}

/* The assembly under test. Windowed ABI, scratch supplied by the caller. */
extern void nistp_mul_mont_8(uint32_t *out, const uint32_t *a, const uint32_t *b,
                             const uint32_t *p, uint32_t *scratch);
extern void nistp_mul_mont_12(uint32_t *out, const uint32_t *a, const uint32_t *b,
                              const uint32_t *p, uint32_t *scratch);
extern void nistp_add_mod_8(uint32_t *out, const uint32_t *a, const uint32_t *b, const uint32_t *p);
extern void nistp_sub_mod_8(uint32_t *out, const uint32_t *a, const uint32_t *b, const uint32_t *p);
extern void nistp_add_mod_12(uint32_t *out, const uint32_t *a, const uint32_t *b, const uint32_t *p);
extern void nistp_sub_mod_12(uint32_t *out, const uint32_t *a, const uint32_t *b, const uint32_t *p);
extern void nistp_sqr_mont_8(uint32_t *out, const uint32_t *a, const uint32_t *p, uint32_t *scratch);
extern void nistp_sqr_mont_12(uint32_t *out, const uint32_t *a, const uint32_t *p, uint32_t *scratch);

typedef void (*mulfn)(uint32_t *, const uint32_t *, const uint32_t *,
                      const uint32_t *, uint32_t *);

static uint32_t scratch[32];

static int eq(const uint32_t *x, const uint32_t *y, int n) {
    for (int i = 0; i < n; i++)
        if (x[i] != y[i]) return 0;
    return 1;
}

/* Runs every vector for one curve. `cases` is treated as a flat array of
 * (a, b, want) triples so one routine serves both limb counts. */
static int run_curve(const char *name, int n, mulfn mul, const uint32_t *P,
                     const uint32_t *R2, const uint32_t *ONE,
                     const uint32_t *cases, int ncases) {
    uint32_t am[12], bm[12], pm[12], got[12];
    int fails = 0;

    for (int i = 0; i < ncases; i++) {
        const uint32_t *a = cases + (size_t)i * 3 * n;
        const uint32_t *b = a + n;
        const uint32_t *want = b + n;

        mul(am, a, R2, P, scratch);      /* a  -> Montgomery form */
        mul(bm, b, R2, P, scratch);      /* b  -> Montgomery form */
        mul(pm, am, bm, P, scratch);     /* the multiply under test */
        mul(got, pm, ONE, P, scratch);   /* back to a plain integer */

        if (!eq(got, want, n)) {
            if (g_results[R_FAILIDX] == 0xFFFFFFFFu) {
                g_results[R_FAILIDX] = (uint32_t)i;
                for (int j = 0; j < n; j++) {
                    if (got[j] != want[j]) {
                        g_results[R_LIMB] = (uint32_t)j;
                        g_results[R_GOT] = got[j];
                        g_results[R_WANT] = want[j];
                        break;
                    }
                }
            }
            fails++;
            puts_("  FAIL "); puts_(name); puts_(" case "); putu_((uint32_t)i);
            puts_("\n    want ");
            for (int j = n - 1; j >= 0; j--) puthex_(want[j]);
            puts_("\n    got  ");
            for (int j = n - 1; j >= 0; j--) puthex_(got[j]);
            putc_('\n');
            if (fails > 3) return fails;
        }
    }
    if (!fails) {
        puts_("  ok   "); puts_(name); puts_(" ("); putu_((uint32_t)ncases);
        puts_(" vectors)\n");
    }
    return fails;
}

/* Cycles for ITERS Montgomery multiplies. */
#define BENCH_ITERS 1000u
static uint32_t bench(int n, mulfn mul, const uint32_t *P, const uint32_t *a,
                      const uint32_t *b) {
    uint32_t out[12];
    for (unsigned i = 0; i < 16; i++) mul(out, a, b, P, scratch);   /* warm */
    uint32_t t0 = ccount();
    for (unsigned i = 0; i < BENCH_ITERS; i++) mul(out, a, b, P, scratch);
    uint32_t t1 = ccount();
    (void)n;
    return t1 - t0;
}

void xmain(void) {
    g_results[R_MAGIC] = 0x4E495354u; /* "NIST" */
    g_results[R_DONE] = 0;
    g_results[R_ITERS] = BENCH_ITERS;
    g_results[R_FAILIDX] = 0xFFFFFFFFu;

    puts_("nistp-mcu Xtensa LX7 on-target tests\n");
    puts_("backend: xtensa-lx7 (SALTU)\n");

    int f256 = run_curve("p256", P256_N, nistp_mul_mont_8, P256_P, P256_R2,
                         P256_ONE, (const uint32_t *)P256_CASES, P256_NCASES);
    int f384 = run_curve("p384", P384_N, nistp_mul_mont_12, P384_P, P384_R2,
                         P384_ONE, (const uint32_t *)P384_CASES, P384_NCASES);
    g_results[R_P256_FAILS] = (uint32_t)f256;
    g_results[R_P384_FAILS] = (uint32_t)f384;

    /* Benchmark on Montgomery-form operands (case 8 is a random pair). */
    uint32_t am[12], bm[12];
    nistp_mul_mont_8(am, P256_CASES[8][0], P256_R2, P256_P, scratch);
    nistp_mul_mont_8(bm, P256_CASES[8][1], P256_R2, P256_P, scratch);
    g_results[R_P256_CYCLES] = bench(8, nistp_mul_mont_8, P256_P, am, bm);

    nistp_mul_mont_12(am, P384_CASES[8][0], P384_R2, P384_P, scratch);
    nistp_mul_mont_12(bm, P384_CASES[8][1], P384_R2, P384_P, scratch);
    g_results[R_P384_CYCLES] = bench(12, nistp_mul_mont_12, P384_P, am, bm);

    /* Cross-check fiat against ours before timing: comparing two routines is
     * only meaningful once they are proven to compute the same thing. */
    {
        uint32_t ours[12], theirs[12];
        uint32_t a8[8], b8[8], a12[12], b12[12];
        nistp_mul_mont_8(a8, P256_CASES[8][0], P256_R2, P256_P, scratch);
        nistp_mul_mont_8(b8, P256_CASES[8][1], P256_R2, P256_P, scratch);
        nistp_mul_mont_8(ours, a8, b8, P256_P, scratch);
        fiat_p256_mul_ext(theirs, a8, b8);
        int ok = eq(ours, theirs, 8);

        nistp_mul_mont_12(a12, P384_CASES[8][0], P384_R2, P384_P, scratch);
        nistp_mul_mont_12(b12, P384_CASES[8][1], P384_R2, P384_P, scratch);
        nistp_mul_mont_12(ours, a12, b12, P384_P, scratch);
        fiat_p384_mul_ext(theirs, a12, b12);
        ok = ok && eq(ours, theirs, 12);
        g_results[R_CROSSCHECK] = ok ? 0x0000000Bu : 0xBADBAD00u;

        /* Baseline timings, same iteration count as ours. */
        uint32_t t0 = ccount();
        for (unsigned i = 0; i < BENCH_ITERS; i++) fiat_p256_mul_ext(ours, a8, b8);
        g_results[R_FIAT_P256_CYCLES] = ccount() - t0;

        t0 = ccount();
        for (unsigned i = 0; i < BENCH_ITERS; i++) fiat_p384_mul_ext(ours, a12, b12);
        g_results[R_FIAT_P384_CYCLES] = ccount() - t0;
    }

    /* Add/sub correctness and benchmarks */
    int add_sub_fails = 0;
    for (int i = 0; i < P256_NCASES; i++) {
        uint32_t s[8], d[8], rec[8];
        const uint32_t *a = P256_CASES[i][0];
        const uint32_t *b = P256_CASES[i][1];
        nistp_add_mod_8(s, a, b, P256_P);
        nistp_sub_mod_8(rec, s, b, P256_P);
        if (!eq(rec, a, 8)) add_sub_fails++;
        nistp_sub_mod_8(d, a, b, P256_P);
        nistp_add_mod_8(rec, d, b, P256_P);
        if (!eq(rec, a, 8)) add_sub_fails++;
    }
    for (int i = 0; i < P384_NCASES; i++) {
        uint32_t s[12], d[12], rec[12];
        const uint32_t *a = P384_CASES[i][0];
        const uint32_t *b = P384_CASES[i][1];
        nistp_add_mod_12(s, a, b, P384_P);
        nistp_sub_mod_12(rec, s, b, P384_P);
        if (!eq(rec, a, 12)) add_sub_fails++;
        nistp_sub_mod_12(d, a, b, P384_P);
        nistp_add_mod_12(rec, d, b, P384_P);
        if (!eq(rec, a, 12)) add_sub_fails++;
    }
    g_results[R_ADD_SUB_FAILS] = (uint32_t)add_sub_fails;

    {
        uint32_t s8[8], s12[12];
        const uint32_t *a8 = P256_CASES[8][0];
        const uint32_t *b8 = P256_CASES[8][1];
        const uint32_t *a12 = P384_CASES[8][0];
        const uint32_t *b12 = P384_CASES[8][1];

        uint32_t t0 = ccount();
        for (unsigned i = 0; i < BENCH_ITERS; i++) nistp_add_mod_8(s8, a8, b8, P256_P);
        g_results[R_P256_ADD_CYCLES] = ccount() - t0;

        t0 = ccount();
        for (unsigned i = 0; i < BENCH_ITERS; i++) nistp_sub_mod_8(s8, a8, b8, P256_P);
        g_results[R_P256_SUB_CYCLES] = ccount() - t0;

        t0 = ccount();
        for (unsigned i = 0; i < BENCH_ITERS; i++) nistp_add_mod_12(s12, a12, b12, P384_P);
        g_results[R_P384_ADD_CYCLES] = ccount() - t0;

        t0 = ccount();
        for (unsigned i = 0; i < BENCH_ITERS; i++) nistp_sub_mod_12(s12, a12, b12, P384_P);
        g_results[R_P384_SUB_CYCLES] = ccount() - t0;
    }

    /* Squaring correctness and benchmarks */
    int sqr_fails = 0;
    for (int i = 0; i < P256_NCASES; i++) {
        uint32_t sqr_res[8], mul_res[8];
        const uint32_t *a = P256_CASES[i][0];
        nistp_sqr_mont_8(sqr_res, a, P256_P, scratch);
        nistp_mul_mont_8(mul_res, a, a, P256_P, scratch);
        if (!eq(sqr_res, mul_res, 8)) sqr_fails++;
    }
    for (int i = 0; i < P384_NCASES; i++) {
        uint32_t sqr_res[12], mul_res[12];
        const uint32_t *a = P384_CASES[i][0];
        nistp_sqr_mont_12(sqr_res, a, P384_P, scratch);
        nistp_mul_mont_12(mul_res, a, a, P384_P, scratch);
        if (!eq(sqr_res, mul_res, 12)) sqr_fails++;
    }
    g_results[R_SQR_FAILS] = (uint32_t)sqr_fails;

    {
        uint32_t am8[8], am12[12], out8[8], out12[12];
        nistp_mul_mont_8(am8, P256_CASES[8][0], P256_R2, P256_P, scratch);
        nistp_mul_mont_12(am12, P384_CASES[8][0], P384_R2, P384_P, scratch);

        uint32_t t0 = ccount();
        for (unsigned i = 0; i < BENCH_ITERS; i++) nistp_sqr_mont_8(out8, am8, P256_P, scratch);
        g_results[R_P256_SQR_CYCLES] = ccount() - t0;

        t0 = ccount();
        for (unsigned i = 0; i < BENCH_ITERS; i++) nistp_sqr_mont_12(out12, am12, P384_P, scratch);
        g_results[R_P384_SQR_CYCLES] = ccount() - t0;
    }

    if (!(f256 + f384 + add_sub_fails + sqr_fails)) puts_("ALL PASS\n");
    else { puts_("FAILURES: "); putu_((uint32_t)(f256 + f384 + add_sub_fails + sqr_fails)); putc_('\n'); }
    puts_("p256 cycles/1000: "); putu_(g_results[R_P256_CYCLES]); putc_('\n');
    puts_("p384 cycles/1000: "); putu_(g_results[R_P384_CYCLES]); putc_('\n');

    g_results[R_DONE] = 0xD09E0000u;
}

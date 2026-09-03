/* External wrappers around fiat-crypto's static-inline field multiplies, so
 * the benchmark harness can call them. */
#include <stdint.h>
#include "p256_32.c"
#include "p384_32.c"

void fiat_p256_mul_ext(uint32_t *out, const uint32_t *a, const uint32_t *b) {
    fiat_p256_mul(out, a, b);
}
void fiat_p384_mul_ext(uint32_t *out, const uint32_t *a, const uint32_t *b) {
    fiat_p384_mul(out, a, b);
}

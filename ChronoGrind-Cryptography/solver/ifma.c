// Almost-Montgomery repeated squaring, radix 2^52, 40 limbs (R = 2^2080), AVX-512 IFMA.
// stdin: k0 count  N[40] x[40]   (decimal 52-bit limbs, little-endian)
// stdout: x[40] after `count` squarings (x <- x*x/R mod N, lazy, < 2N)
#include <immintrin.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#define NL 40
#define NV 5
#define MASK52 ((1ULL<<52)-1)

static uint64_t Nl[NL];
static __m512i Mv[NV];
static uint64_t K0;

static inline void amm(uint64_t *out, const uint64_t *a) {
    __m512i A[NV], R[NV];
    for (int k = 0; k < NV; k++) { A[k] = _mm512_loadu_si512(a + 8*k); R[k] = _mm512_setzero_si512(); }
    const __m512i zero = _mm512_setzero_si512();
    for (int i = 0; i < NL; i++) {
        uint64_t bi = a[i];
        __m512i B = _mm512_set1_epi64((long long)bi);
        for (int k = 0; k < NV; k++) R[k] = _mm512_madd52lo_epu64(R[k], A[k], B);
        uint64_t t = (uint64_t)_mm_cvtsi128_si64(_mm512_castsi512_si128(R[0]));
        uint64_t y = (t * K0) & MASK52;
        __m512i Y = _mm512_set1_epi64((long long)y);
        for (int k = 0; k < NV; k++) R[k] = _mm512_madd52lo_epu64(R[k], Mv[k], Y);
        uint64_t carry = (t + ((Nl[0] * y) & MASK52)) >> 52;
        for (int k = 0; k < NV-1; k++) R[k] = _mm512_alignr_epi64(R[k+1], R[k], 1);
        R[NV-1] = _mm512_alignr_epi64(zero, R[NV-1], 1);
        R[0] = _mm512_mask_add_epi64(R[0], 1, R[0], _mm512_set1_epi64((long long)carry));
        for (int k = 0; k < NV; k++) R[k] = _mm512_madd52hi_epu64(R[k], A[k], B);
        for (int k = 0; k < NV; k++) R[k] = _mm512_madd52hi_epu64(R[k], Mv[k], Y);
    }
    uint64_t tmp[NL];
    for (int k = 0; k < NV; k++) _mm512_storeu_si512(tmp + 8*k, R[k]);
    uint64_t c = 0;
    for (int j = 0; j < NL; j++) { uint64_t v = tmp[j] + c; out[j] = v & MASK52; c = v >> 52; }
}

int main(void) {
    unsigned long long count;
    if (scanf("%llu %llu", (unsigned long long*)&K0, &count) != 2) return 1;
    for (int j = 0; j < NL; j++) scanf("%llu", (unsigned long long*)&Nl[j]);
    uint64_t x[NL] __attribute__((aligned(64)));
    for (int j = 0; j < NL; j++) scanf("%llu", (unsigned long long*)&x[j]);
    for (int k = 0; k < NV; k++) Mv[k] = _mm512_loadu_si512(Nl + 8*k);
    uint64_t y[NL] __attribute__((aligned(64)));
    for (unsigned long long it = 0; it < count; it += 2) {
        amm(y, x);
        if (it + 1 < count) amm(x, y); else memcpy(x, y, sizeof x);
    }
    for (int j = 0; j < NL; j++) printf("%llu ", (unsigned long long)x[j]);
    printf("\n");
    return 0;
}

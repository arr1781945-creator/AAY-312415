#pragma once
#include <array>
#include <cstdint>
#include <cstring>

// ─── CLEAN NTT IMPLEMENTATION ────────────────────────────────
// Based on Python reference: root=17, root_inv=1175, n_inv=3316

static constexpr int N = 256;
static constexpr int16_t Q = 3329;
static constexpr int16_t ROOT = 17;
static constexpr int16_t ROOT_INV = 1175;
static constexpr int16_t N_INV = 3316;

using Poly = std::array<int16_t, N>;

// Modular reduction
inline int16_t mod_q(int64_t x) {
    x %= Q;
    return (int16_t)(x < 0 ? x + Q : x);
}

// Power function: base^exp mod Q
inline int16_t pow_mod(int16_t base, int exp, int16_t mod) {
    int64_t result = 1;
    int64_t b = base;
    while (exp > 0) {
        if (exp & 1) result = (result * b) % mod;
        b = (b * b) % mod;
        exp >>= 1;
    }
    return (int16_t)result;
}

// Bit reversal permutation
inline void bit_rev(Poly& a) {
    for (int i = 0; i < N; i++) {
        int j = 0;
        for (int k = 0; k < 8; k++) {  // log2(256)=8
            if (i & (1 << k)) j |= (1 << (7 - k));
        }
        if (i < j) std::swap(a[i], a[j]);
    }
}

// NTT Forward
inline void ntt(Poly& a) {
    bit_rev(a);
    
    for (int len = 2; len <= N; len <<= 1) {
        int16_t w = pow_mod(ROOT, N / len, Q);
        
        for (int i = 0; i < N; i += len) {
            int16_t wn = 1;
            for (int j = 0; j < len / 2; j++) {
                int64_t u = a[i + j];
                int64_t v = ((int64_t)a[i + j + len/2] * wn) % Q;
                a[i + j] = mod_q(u + v);
                a[i + j + len/2] = mod_q(u - v);
                wn = (int16_t)(((int64_t)wn * w) % Q);
            }
        }
    }
}

// NTT Inverse
inline void ntt_inv(Poly& a) {
    bit_rev(a);
    
    for (int len = 2; len <= N; len <<= 1) {
        int16_t w = pow_mod(ROOT_INV, N / len, Q);
        
        for (int i = 0; i < N; i += len) {
            int16_t wn = 1;
            for (int j = 0; j < len / 2; j++) {
                int64_t u = a[i + j];
                int64_t v = ((int64_t)a[i + j + len/2] * wn) % Q;
                a[i + j] = mod_q(u + v);
                a[i + j + len/2] = mod_q(u - v);
                wn = (int16_t)(((int64_t)wn * w) % Q);
            }
        }
    }
    
    for (int i = 0; i < N; i++) {
        a[i] = mod_q((int64_t)a[i] * N_INV);
    }
}

// Pointwise multiply
inline Poly pointwise_mul(const Poly& a, const Poly& b) {
    Poly c = {};
    for (int i = 0; i < N; i++) {
        c[i] = mod_q((int64_t)a[i] * b[i]);
    }
    return c;
}

// NTT multiply
inline Poly ntt_mul(Poly a, Poly b) {
    ntt(a);
    ntt(b);
    auto c = pointwise_mul(a, b);
    ntt_inv(c);
    return c;
}

#ifdef NTT_CLEAN_TEST
#include <cstdio>

int main() {
    printf("=== NTT Clean Implementation ===\n\n");
    
    // Test 1: a * 1 = a
    printf("[1] Identity test\n");
    Poly a = {};
    a[0] = 1; a[1] = 2; a[2] = 3;
    
    Poly one = {};
    one[0] = 1;
    
    auto result = ntt_mul(a, one);
    printf("    a: [%d, %d, %d]\n", a[0], a[1], a[2]);
    printf("    a*1: [%d, %d, %d]\n", result[0], result[1], result[2]);
    
    bool ok1 = (result[0] == a[0] && result[1] == a[1] && result[2] == a[2]);
    printf("    [%s] PASS\n\n", ok1 ? "OK" : "FAIL");
    
    // Test 2: a * x = shift
    printf("[2] Shift test (a*x)\n");
    Poly x = {};
    x[1] = 1;
    
    Poly simple = {};
    simple[0] = 5;
    simple[1] = 3;
    
    auto shifted = ntt_mul(simple, x);
    printf("    (5+3x)*x: [%d, %d, %d]\n", shifted[0], shifted[1], shifted[2]);
    printf("    Expected negacyclic: [0, 5, 3] or with wrap\n");
    
    // Test 3: Commutativity
    printf("\n[3] Commutativity (a*b = b*a)\n");
    Poly b = {};
    b[0] = 10;
    b[1] = 20;
    
    auto ab = ntt_mul(a, b);
    auto ba = ntt_mul(b, a);
    
    bool ok3 = (std::memcmp(ab.data(), ba.data(), sizeof(Poly)) == 0);
    printf("    [%s] a*b == b*a\n\n", ok3 ? "OK" : "FAIL");
    
    printf("╔════════════════════════════════╗\n");
    printf("║  [%s] NTT Clean Ready          ║\n", (ok1 && ok3) ? "PASS" : "FAIL");
    printf("╚════════════════════════════════╝\n");
    
    return (ok1 && ok3) ? 0 : 1;
}
#endif

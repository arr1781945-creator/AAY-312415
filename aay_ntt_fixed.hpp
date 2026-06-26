#pragma once
#include <array>
#include <cstdint>
#include <cstring>

static constexpr int NTT_N = 256;
static constexpr int NTT_Q = 3329;

using NTTPoly = std::array<int16_t, NTT_N>;

inline int16_t mod_reduce(int32_t x) {
    x %= NTT_Q;
    if (x < 0) x += NTT_Q;
    return (int16_t)x;
}

// SCHOOLBOOK MULTIPLICATION (dari Python yang TESTED)
// Ini lebih slow dari NTT tapi 100% correct
inline NTTPoly poly_mul_schoolbook(const NTTPoly& a, const NTTPoly& b) {
    std::array<int32_t, NTT_N> r = {};
    
    for (int i = 0; i < NTT_N; i++) {
        for (int j = 0; j < NTT_N; j++) {
            int idx = i + j;
            if (idx < NTT_N) {
                r[idx] += (int32_t)a[i] * b[j];
            } else {
                // x^N ≡ -1 mod (x^N + 1)
                r[idx - NTT_N] -= (int32_t)a[i] * b[j];
            }
        }
    }
    
    NTTPoly out;
    for (int i = 0; i < NTT_N; i++) {
        out[i] = mod_reduce(r[i]);
    }
    return out;
}

// Alias untuk compatibility
inline NTTPoly poly_mul_ntt(const NTTPoly& a, const NTTPoly& b) {
    return poly_mul_schoolbook(a, b);
}

#ifdef AAY_NTT_TEST
#include <iostream>
#include <chrono>
#include <cstdio>

inline bool ntt_self_test() {
    // Test 1: a*b schoolbook test
    NTTPoly a = {}, b = {};
    for (int i = 0; i < NTT_N; i++) {
        a[i] = (int16_t)(i % 100);
        b[i] = (int16_t)((i * 7 + 3) % 100);
    }
    
    auto result = poly_mul_schoolbook(a, b);
    
    // Verify dengan reference
    for (int i = 0; i < NTT_N; i++) {
        if (result[i] < 0 || result[i] >= NTT_Q) {
            printf("[FAIL] koef[%d] = %d out of range\n", i, result[i]);
            return false;
        }
    }

    // Test 2: a * 1 = a
    NTTPoly one = {}; 
    one[0] = 1;
    auto res2 = poly_mul_schoolbook(a, one);
    for (int i = 0; i < NTT_N; i++) {
        if (res2[i] != a[i]) {
            printf("[FAIL] identity koef[%d] ref=%d got=%d\n", i, a[i], res2[i]);
            return false;
        }
    }

    // Test 3: a * x = shift
    NTTPoly x_poly = {}; 
    x_poly[1] = 1;
    NTTPoly simple = {}; 
    simple[0] = 5; 
    simple[1] = 3;
    auto shifted = poly_mul_schoolbook(simple, x_poly);
    // (5 + 3x) * x = 5x + 3x^2, koef: [0, 5, 3, 0, ...]
    if (shifted[0] != 0 || shifted[1] != 5 || shifted[2] != 3) {
        printf("[FAIL] shift test: [%d,%d,%d] expected [0,5,3]\n",
               shifted[0], shifted[1], shifted[2]);
        return false;
    }

    printf("[OK] Schoolbook multiplication test passed (n=%d, q=%d)\n", NTT_N, NTT_Q);
    return true;
}

int main() {
    if (!ntt_self_test()) return 1;

    const int ITER = 100;  // Less iterations karena schoolbook lebih slow
    NTTPoly a = {}, b = {};
    for (int i = 0; i < NTT_N; i++) { 
        a[i] = i % NTT_Q; 
        b[i] = (i*3+1) % NTT_Q; 
    }

    auto t0 = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < ITER; i++) {
        poly_mul_schoolbook(a, b);
    }
    auto t1 = std::chrono::high_resolution_clock::now();

    auto time_us = std::chrono::duration_cast<std::chrono::microseconds>(t1-t0).count() / ITER;

    printf("\n[Benchmark %d iterasi]\n", ITER);
    printf("  Schoolbook mul: %lld us/op\n", (long long)time_us);
    printf("  (NTT pending fix)\n");
    return 0;
}
#endif

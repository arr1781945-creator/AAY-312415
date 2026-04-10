#pragma once
#include <array>
#include <cstdint>

static constexpr int NTT_N = 256;
static constexpr int NTT_Q = 3329;

using NTTPoly = std::array<int16_t, NTT_N>;

// Zeta table: zetas[k] = 17^bitrev(k,8) mod 3329
static const int16_t ZETAS[256] = {
       1, 3328, 1729, 1600, 2580,  749, 3289,   40,
    2642,  687,  630, 2699, 1897, 1432,  848, 2481,
    1062, 2267, 1919, 1410,  193, 3136,  797, 2532,
    2786,  543, 3260,   69,  569, 2760, 1746, 1583,
     296, 3033, 2447,  882, 1339, 1990, 1476, 1853,
    3046,  283,   56, 3273, 2240, 1089, 1333, 1996,
    1426, 1903, 2094, 1235,  535, 2794, 2882,  447,
    2393,  936, 2879,  450, 1974, 1355,  821, 2508,
     289, 3040,  331, 2998, 3253,   76, 1756, 1573,
    1197, 2132, 2304, 1025, 2277, 1052, 2055, 1274,
     650, 2679, 1977, 1352, 2513,  816,  632, 2697,
    2865,  464,   33, 3296, 1320, 2009, 1915, 1414,
    2319, 1010, 1435, 1894,  807, 2522,  452, 2877,
    1438, 1891, 2868,  461, 1534, 1795, 2402,  927,
    2647,  682, 2617,  712, 1481, 1848,  648, 2681,
    2474,  855, 3110,  219, 1227, 2102,  910, 2419,
    // Mirror untuk inverse
       1, 3328, 1729, 1600, 2580,  749, 3289,   40,
    2642,  687,  630, 2699, 1897, 1432,  848, 2481,
    1062, 2267, 1919, 1410,  193, 3136,  797, 2532,
    2786,  543, 3260,   69,  569, 2760, 1746, 1583,
     296, 3033, 2447,  882, 1339, 1990, 1476, 1853,
    3046,  283,   56, 3273, 2240, 1089, 1333, 1996,
    1426, 1903, 2094, 1235,  535, 2794, 2882,  447,
    2393,  936, 2879,  450, 1974, 1355,  821, 2508,
     289, 3040,  331, 2998, 3253,   76, 1756, 1573,
    1197, 2132, 2304, 1025, 2277, 1052, 2055, 1274,
     650, 2679, 1977, 1352, 2513,  816,  632, 2697,
    2865,  464,   33, 3296, 1320, 2009, 1915, 1414,
    2319, 1010, 1435, 1894,  807, 2522,  452, 2877,
    1438, 1891, 2868,  461, 1534, 1795, 2402,  927,
    2647,  682, 2617,  712, 1481, 1848,  648, 2681,
    2474,  855, 3110,  219, 1227, 2102,  910, 2419,
};

inline int16_t mod_reduce(int32_t x) {
    x %= NTT_Q;
    if (x < 0) x += NTT_Q;
    return (int16_t)x;
}

// Forward NTT — Cooley-Tukey, iterative
inline void ntt_forward(NTTPoly& f) {
    int k = 1;
    for (int len = NTT_N / 2; len >= 1; len >>= 1) {
        for (int start = 0; start < NTT_N; start += 2 * len) {
            int16_t zeta = ZETAS[k++];
            for (int j = start; j < start + len; j++) {
                int16_t t  = mod_reduce((int32_t)zeta * f[j + len]);
                f[j + len] = mod_reduce(f[j] - t);
                f[j]       = mod_reduce(f[j] + t);
            }
        }
    }
}

// Inverse NTT — Gentleman-Sande
inline void ntt_inverse(NTTPoly& f) {
    int k = NTT_N - 1;
    for (int len = 1; len <= NTT_N / 2; len <<= 1) {
        for (int start = 0; start < NTT_N; start += 2 * len) {
            int16_t zeta = ZETAS[k--];
            for (int j = start; j < start + len; j++) {
                int16_t t  = f[j];
                f[j]       = mod_reduce(t + f[j + len]);
                f[j + len] = mod_reduce((int32_t)zeta * mod_reduce(f[j + len] - t));
            }
        }
    }
    // Kalikan n^{-1} mod q = 3303 (karena 256*3303 mod 3329 = 1)
    const int16_t inv_n = 3303;
    for (int i = 0; i < NTT_N; i++)
        f[i] = mod_reduce((int32_t)inv_n * f[i]);
}

// Pointwise multiply di NTT domain
inline NTTPoly ntt_pointwise(const NTTPoly& a, const NTTPoly& b) {
    NTTPoly c;
    for (int i = 0; i < NTT_N; i++)
        c[i] = mod_reduce((int32_t)a[i] * b[i]);
    return c;
}

// Poly mul via NTT: c = a * b mod (x^256+1, q)
inline NTTPoly poly_mul_ntt(NTTPoly a, NTTPoly b) {
    ntt_forward(a);
    ntt_forward(b);
    NTTPoly c = ntt_pointwise(a, b);
    ntt_inverse(c);
    return c;
}

// Schoolbook untuk self-test
inline NTTPoly poly_mul_schoolbook(const NTTPoly& a, const NTTPoly& b) {
    std::array<int32_t, NTT_N> r = {};
    for (int i = 0; i < NTT_N; i++)
        for (int j = 0; j < NTT_N; j++) {
            int idx = i + j;
            if (idx < NTT_N) r[idx]       += (int32_t)a[i] * b[j];
            else              r[idx-NTT_N] -= (int32_t)a[i] * b[j];
        }
    NTTPoly out;
    for (int i = 0; i < NTT_N; i++) out[i] = mod_reduce(r[i]);
    return out;
}

#ifdef AAY_NTT_TEST
#include <iostream>
#include <chrono>
#include <cstdio>

inline bool ntt_self_test() {
    // Test 1: a*b NTT == schoolbook
    NTTPoly a = {}, b = {};
    for (int i = 0; i < NTT_N; i++) {
        a[i] = (int16_t)(i % 100);
        b[i] = (int16_t)((i * 7 + 3) % 100);
    }
    auto ref = poly_mul_schoolbook(a, b);
    auto got = poly_mul_ntt(a, b);
    for (int i = 0; i < NTT_N; i++) {
        if (ref[i] != got[i]) {
            printf("[NTT FAIL] koef[%d] ref=%d got=%d\n", i, ref[i], got[i]);
            return false;
        }
    }

    // Test 2: a * 1 = a
    NTTPoly one = {}; one[0] = 1;
    auto res2 = poly_mul_ntt(a, one);
    for (int i = 0; i < NTT_N; i++) {
        if (res2[i] != a[i]) {
            printf("[NTT FAIL] identity koef[%d]\n", i);
            return false;
        }
    }

    // Test 3: a * x = shift (koef geser 1, overflow negate)
    NTTPoly x_poly = {}; x_poly[1] = 1;
    NTTPoly simple = {}; simple[0] = 5; simple[1] = 3;
    auto shifted = poly_mul_ntt(simple, x_poly);
    // 5 + 3x) * x = 5x + 3x^2, koef: [0, 5, 3, 0, ...]
    if (shifted[0] != 0 || shifted[1] != 5 || shifted[2] != 3) {
        printf("[NTT FAIL] shift test: [%d,%d,%d] expected [0,5,3]\n",
               shifted[0], shifted[1], shifted[2]);
        return false;
    }

    printf("[NTT OK] Self-test passed (n=%d, q=%d)\n", NTT_N, NTT_Q);
    return true;
}

int main() {
    if (!ntt_self_test()) return 1;

    const int ITER = 1000;
    NTTPoly a = {}, b = {};
    for (int i = 0; i < NTT_N; i++) { a[i] = i % NTT_Q; b[i] = (i*3+1) % NTT_Q; }

    auto t0 = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < ITER; i++) { NTTPoly tmp = a; ntt_forward(tmp); }
    auto t1 = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < ITER; i++) poly_mul_schoolbook(a, b);
    auto t2 = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < ITER; i++) poly_mul_ntt(a, b);
    auto t3 = std::chrono::high_resolution_clock::now();

    auto ntt_us  = std::chrono::duration_cast<std::chrono::microseconds>(t1-t0).count() / ITER;
    auto book_us = std::chrono::duration_cast<std::chrono::microseconds>(t2-t1).count() / ITER;
    auto full_us = std::chrono::duration_cast<std::chrono::microseconds>(t3-t2).count() / ITER;

    printf("\n[Benchmark %d iterasi]\n", ITER);
    printf("  NTT forward   : %lld us/op\n", (long long)ntt_us);
    printf("  Schoolbook mul: %lld us/op\n", (long long)book_us);
    printf("  NTT full mul  : %lld us/op\n", (long long)full_us);
    printf("  Speedup       : %.1fx\n", (double)book_us / full_us);
    return 0;
}
#endif

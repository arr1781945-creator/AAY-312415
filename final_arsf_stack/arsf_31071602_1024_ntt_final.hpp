#pragma once
#include <array>
#include <cstdint>
#include "arsf_31071602_1024_params.hpp"
#include "zeta_arsf_31071602_1024.hpp"

using namespace ARSF31071602_1024;
using NTTPoly1024 = std::array<int16_t, N>;

inline int16_t mod_reduce(int32_t x) {
    x %= Q;
    if (x < 0) x += Q;
    return (int16_t)x;
}

// KYBER STYLE - EXACT SAME LOGIC
// Forward NTT (Cooley-Tukey)
inline void ntt_forward_arsf_1024(NTTPoly1024& f) {
    int k = 1;
    for (int len = N / 2; len >= 1; len >>= 1) {
        for (int start = 0; start < N; start += 2 * len) {
            int16_t zeta = ZETAS[k++];
            for (int j = start; j < start + len; j++) {
                int16_t t = mod_reduce((int32_t)zeta * f[j + len]);
                f[j + len] = mod_reduce(f[j] - t);
                f[j] = mod_reduce(f[j] + t);
            }
        }
    }
}

// Inverse NTT (Gentleman-Sande) - KYBER EXACT STYLE
inline void ntt_inverse_arsf_1024(NTTPoly1024& f) {
    int k = 127;  // Kyber uses k = 127 untuk n=256, adjust for n=1024
    for (int len = 1; len < N; len <<= 1) {
        for (int start = 0; start < N; start += 2 * len) {
            int16_t zeta = ZETAS[k--];
            for (int j = start; j < start + len; j++) {
                int16_t t = f[j];
                f[j] = mod_reduce(t + f[j + len]);
                f[j + len] = mod_reduce(f[j + len] - t);
                f[j + len] = mod_reduce((int32_t)zeta * f[j + len]);
            }
        }
    }
    
    // Multiply by N^(-1)
    const int16_t n_inv = (int16_t)(N_INV % Q);
    for (int i = 0; i < N; i++)
        f[i] = mod_reduce((int32_t)n_inv * f[i]);
}

// Pointwise multiply di NTT domain
inline NTTPoly1024 ntt_pointwise_arsf_1024(const NTTPoly1024& a, const NTTPoly1024& b) {
    NTTPoly1024 c;
    for (int i = 0; i < N; i++)
        c[i] = mod_reduce((int32_t)a[i] * b[i]);
    return c;
}

// Polynomial multiplication via NTT (Kyber style)
inline NTTPoly1024 poly_mul_ntt_arsf_1024(NTTPoly1024 a, NTTPoly1024 b) {
    ntt_forward_arsf_1024(a);
    ntt_forward_arsf_1024(b);
    NTTPoly1024 c = ntt_pointwise_arsf_1024(a, b);
    ntt_inverse_arsf_1024(c);
    return c;
}

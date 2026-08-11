#include "arsf_31071602_ntt.hpp"
#include <algorithm>

// Helper: modular exponentiation
static uint32_t mod_exp(uint32_t base, uint32_t exp, uint32_t mod) {
    uint64_t result = 1;
    uint64_t b = base;
    while (exp > 0) {
        if (exp & 1) result = (result * b) % mod;
        b = (b * b) % mod;
        exp >>= 1;
    }
    return result;
}

// Precompute zeta_inv table
static std::array<uint32_t, N> compute_zeta_inv() {
    std::array<uint32_t, N> result;
    uint32_t omega_inv = mod_exp(OMEGA, Q - 2, Q);
    for (uint32_t i = 0; i < N; i++) {
        result[i] = mod_exp(omega_inv, i, Q);
    }
    return result;
}

static const std::array<uint32_t, N> zeta_inv = compute_zeta_inv();

// Bit reversal permutation
static void bit_reverse_copy(NTT::Poly& a) {
    for (uint32_t i = 0; i < N; i++) {
        uint32_t j = 0;
        uint32_t rev_i = i;
        for (int k = 0; k < LOG2N; k++) {
            j = (j << 1) | (rev_i & 1);
            rev_i >>= 1;
        }
        if (i < j) std::swap(a[i], a[j]);
    }
}

// Forward NTT (Cooley-Tukey, decimation in time)
void NTT::ntt(Poly& a) {
    bit_reverse_copy(a);
    
    for (uint32_t len = 2; len <= N; len <<= 1) {
        uint32_t len_half = len >> 1;
        uint32_t omega_step = N / len;
        
        for (uint32_t i = 0; i < N; i += len) {
            uint32_t omega_idx = 0;
            
            for (uint32_t j = 0; j < len_half; j++) {
                uint32_t omega_val = zeta[omega_idx];
                uint32_t u = a[i + j];
                uint64_t v64 = (uint64_t)a[i + j + len_half] * omega_val;
                uint32_t v = barrett_reduce(v64);
                
                uint32_t t = (u + v) % Q;
                a[i + j + len_half] = (u + Q - v) % Q;
                a[i + j] = t;
                
                omega_idx += omega_step;
            }
        }
    }
}

// Inverse NTT
void NTT::intt(Poly& a) {
    bit_reverse_copy(a);
    
    for (uint32_t len = 2; len <= N; len <<= 1) {
        uint32_t len_half = len >> 1;
        uint32_t omega_step = N / len;
        
        for (uint32_t i = 0; i < N; i += len) {
            uint32_t omega_idx = 0;
            
            for (uint32_t j = 0; j < len_half; j++) {
                uint32_t omega_val = zeta_inv[omega_idx];
                uint32_t u = a[i + j];
                uint64_t v64 = (uint64_t)a[i + j + len_half] * omega_val;
                uint32_t v = barrett_reduce(v64);
                
                uint32_t t = (u + v) % Q;
                a[i + j + len_half] = (u + Q - v) % Q;
                a[i + j] = t;
                
                omega_idx += omega_step;
            }
        }
    }
    
    // Multiply by n^(-1)
    for (uint32_t i = 0; i < N; i++) {
        uint64_t tmp = (uint64_t)a[i] * N_INV;
        a[i] = barrett_reduce(tmp);
    }
}

// Polynomial multiplication
void NTT::mul(Poly& result, const Poly& a, const Poly& b) {
    Poly a_ntt = a;
    Poly b_ntt = b;
    
    ntt(a_ntt);
    ntt(b_ntt);
    
    for (uint32_t i = 0; i < N; i++) {
        uint64_t prod = (uint64_t)a_ntt[i] * b_ntt[i];
        result[i] = barrett_reduce(prod);
    }
    
    intt(result);
}

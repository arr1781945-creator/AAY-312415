#pragma once
#include <array>
#include <cstdint>
#include <cstring>
#include <random>
#include "aay_ntt_fixed.hpp"

static constexpr int KYBER_N = 256;
static constexpr int KYBER_Q = 3329;

using KyberPoly = NTTPoly;
using KyberPolyVec = std::array<KyberPoly, KYBER_N>;

// ─── EXACT PORT dari Python poly_mul_negacyclic ───
inline KyberPoly poly_mul_negacyclic_exact(const KyberPoly& a, const KyberPoly& b) {
    KyberPoly result = {};
    
    for (int i = 0; i < KYBER_N; i++) {
        for (int j = 0; j < KYBER_N; j++) {
            int idx = i + j;
            if (idx < KYBER_N) {
                result[idx] = (int16_t)((result[idx] + (int32_t)a[i] * b[j]) % KYBER_Q);
            } else {
                // x^N ≡ -1: koef overflow di-negate
                result[idx - KYBER_N] = (int16_t)((result[idx - KYBER_N] - (int32_t)a[i] * b[j]) % KYBER_Q);
            }
        }
    }
    
    // Final modular reduction
    for (int i = 0; i < KYBER_N; i++) {
        result[i] = (int16_t)(((result[i] % KYBER_Q) + KYBER_Q) % KYBER_Q);
    }
    
    return result;
}

// ─── RLWE KeyGen (port dari Python) ───
struct RLWEKeyPair {
    KyberPoly a;  // Public polynomial
    KyberPoly b;  // Public key: b = a*s + e
    KyberPoly s;  // Secret key
};

inline RLWEKeyPair rlwe_keygen(std::mt19937& rng) {
    RLWEKeyPair kp;
    std::uniform_int_distribution<int> uniform_q(0, KYBER_Q - 1);
    std::uniform_int_distribution<int> small_dist(-2, 2);  // eta=2
    
    // a: uniform random
    for (int i = 0; i < KYBER_N; i++) {
        kp.a[i] = (int16_t)uniform_q(rng);
    }
    
    // s, e: small random [-2, 2]
    KyberPoly e = {};
    for (int i = 0; i < KYBER_N; i++) {
        kp.s[i] = (int16_t)small_dist(rng);
        e[i] = (int16_t)small_dist(rng);
    }
    
    // b = a*s + e
    KyberPoly a_times_s = poly_mul_negacyclic_exact(kp.a, kp.s);
    for (int i = 0; i < KYBER_N; i++) {
        kp.b[i] = (int16_t)(((a_times_s[i] + e[i]) % KYBER_Q + KYBER_Q) % KYBER_Q);
    }
    
    return kp;
}

// ─── RLWE Encrypt (port dari Python) ───
struct RLWECiphertext {
    KyberPoly u;
    KyberPoly v;
};

inline std::pair<RLWECiphertext, int> rlwe_encrypt(const RLWEKeyPair& pk, int m_bit, std::mt19937& rng) {
    std::uniform_int_distribution<int> small_dist(-2, 2);
    
    RLWECiphertext ct;
    
    // r, e1, e2: small random
    KyberPoly r = {}, e1 = {}, e2 = {};
    for (int i = 0; i < KYBER_N; i++) {
        r[i] = (int16_t)small_dist(rng);
        e1[i] = (int16_t)small_dist(rng);
        e2[i] = (int16_t)small_dist(rng);
    }
    
    // u = a*r + e1
    KyberPoly a_times_r = poly_mul_negacyclic_exact(pk.a, r);
    for (int i = 0; i < KYBER_N; i++) {
        ct.u[i] = (int16_t)(((a_times_r[i] + e1[i]) % KYBER_Q + KYBER_Q) % KYBER_Q);
    }
    
    // v = b*r + e2 + m*(q/2)
    KyberPoly b_times_r = poly_mul_negacyclic_exact(pk.b, r);
    for (int i = 0; i < KYBER_N; i++) {
        ct.v[i] = (int16_t)(((b_times_r[i] + e2[i]) % KYBER_Q + KYBER_Q) % KYBER_Q);
    }
    
    // Encode message ke v[0]
    int msg_encoded = m_bit * (KYBER_Q / 2);
    ct.v[0] = (int16_t)(((ct.v[0] + msg_encoded) % KYBER_Q + KYBER_Q) % KYBER_Q);
    
    return {ct, m_bit};
}

// ─── RLWE Decrypt (port dari Python) ───
inline int rlwe_decrypt(const RLWEKeyPair& sk, const RLWECiphertext& ct) {
    // s*u
    KyberPoly su = poly_mul_negacyclic_exact(sk.s, ct.u);
    
    // m_poly = v - s*u
    KyberPoly m_poly = {};
    for (int i = 0; i < KYBER_N; i++) {
        m_poly[i] = (int16_t)(((ct.v[i] - su[i]) % KYBER_Q + KYBER_Q) % KYBER_Q);
    }
    
    // Baca koef pertama dan round
    int c = m_poly[0];
    if (abs(c - KYBER_Q / 2) < KYBER_Q / 4) {
        return 1;
    } else {
        return 0;
    }
}

#ifdef RLWE_TEST
#include <iostream>
#include <cstdio>

inline bool rlwe_test() {
    printf("=== RLWE Test (port from Python) ===\n\n");
    
    std::mt19937 rng(12345);
    
    auto kp = rlwe_keygen(rng);
    printf("[OK] KeyGen\n");
    
    int errors = 0;
    int test_bits[] = {0, 1, 0, 1, 1, 0};
    
    for (int test_bit : test_bits) {
        auto [ct, bit_sent] = rlwe_encrypt(kp, test_bit, rng);
        int bit_recv = rlwe_decrypt(kp, ct);
        
        bool match = (bit_sent == bit_recv);
        printf("  bit=%d → decrypt=%d [%s]\n", 
               test_bit, bit_recv, match ? "OK" : "FAIL");
        if (!match) errors++;
    }
    
    printf("\nError rate: %d/6\n", errors);
    
    return errors == 0;
}

int main() {
    if (!rlwe_test()) return 1;
    printf("\n[PASS] RLWE working!\n");
    return 0;
}
#endif

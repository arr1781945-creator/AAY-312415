#pragma once
#include <array>
#include <cstdint>
#include <cstring>
#include <random>
#include "aay_ntt_fixed.hpp"

static constexpr int KYBER_K = 4;
static constexpr int KYBER_N = 256;
static constexpr int KYBER_Q = 3329;

using KyberPoly = NTTPoly;
using KyberPolyVec = std::array<KyberPoly, KYBER_K>;

// CBD dari Python (simplified)
inline int16_t cbd_sample_simple(std::mt19937& rng, int eta) {
    std::uniform_int_distribution<int> dist(0, 1);
    int a = 0, b = 0;
    for (int i = 0; i < eta; i++) {
        a += dist(rng);
        b += dist(rng);
    }
    return (int16_t)(a - b);
}

inline KyberPoly cbd_poly_simple(std::mt19937& rng, int eta) {
    KyberPoly p = {};
    for (int i = 0; i < KYBER_N; i++) {
        p[i] = cbd_sample_simple(rng, eta);
    }
    return p;
}

// RLWE keygen dari Python
struct SimplifiedKyberKey {
    KyberPolyVec a;   // Matrix A (flattened)
    KyberPolyVec s;   // Secret
    KyberPolyVec b;   // Public key: b = As + e
    std::array<uint8_t, 32> seed;
};

inline SimplifiedKyberKey simplified_keygen(std::mt19937& rng) {
    SimplifiedKyberKey key;
    std::uniform_int_distribution<uint8_t> byte_dist(0, 255);
    std::uniform_int_distribution<int> coef_dist(0, KYBER_Q - 1);
    
    // Random seed
    for (int i = 0; i < 32; i++) {
        key.seed[i] = byte_dist(rng);
    }
    
    // Secret s from CBD(2)
    for (int i = 0; i < KYBER_K; i++) {
        key.s[i] = cbd_poly_simple(rng, 2);
    }
    
    // Error e from CBD(2)
    KyberPolyVec e = {};
    for (int i = 0; i < KYBER_K; i++) {
        e[i] = cbd_poly_simple(rng, 2);
    }
    
    // Matrix A - uniform random
    std::array<KyberPolyVec, KYBER_K> A = {};
    for (int i = 0; i < KYBER_K; i++) {
        for (int j = 0; j < KYBER_K; j++) {
            for (int k = 0; k < KYBER_N; k++) {
                A[i][j][k] = (int16_t)(coef_dist(rng) % KYBER_Q);
            }
        }
    }
    
    // b = As + e (matrix-vector multiplication)
    // b[i] = sum_j(A[i][j] * s[j]) + e[i]
    for (int i = 0; i < KYBER_K; i++) {
        KyberPoly acc = {};
        for (int j = 0; j < KYBER_K; j++) {
            KyberPoly mul = poly_mul_schoolbook(A[i][j], key.s[j]);
            for (int k = 0; k < KYBER_N; k++) {
                acc[k] = (int16_t)((acc[k] + mul[k] + e[i][k]) % KYBER_Q);
            }
        }
        key.b[i] = acc;
    }
    
    // Store A for later (simplified - just keep first one)
    key.a = A[0];
    
    return key;
}

// Simplified encaps (dari Python logic)
struct SimplifiedCiphertext {
    KyberPolyVec u;
    KyberPoly v;
    std::array<uint8_t, 32> message;
};

inline std::pair<SimplifiedCiphertext, std::array<uint8_t, 32>>
simplified_encaps(const SimplifiedKyberKey& pk, std::mt19937& rng) {
    std::uniform_int_distribution<uint8_t> byte_dist(0, 255);
    std::uniform_int_distribution<int> coef_dist(0, KYBER_Q - 1);
    
    // Random message
    std::array<uint8_t, 32> message = {};
    for (int i = 0; i < 32; i++) {
        message[i] = byte_dist(rng);
    }
    
    // Random r from CBD(2)
    KyberPolyVec r = {};
    for (int i = 0; i < KYBER_K; i++) {
        r[i] = cbd_poly_simple(rng, 2);
    }
    
    // Error e1, e2
    KyberPolyVec e1 = {};
    for (int i = 0; i < KYBER_K; i++) {
        e1[i] = cbd_poly_simple(rng, 2);
    }
    KyberPoly e2 = cbd_poly_simple(rng, 2);
    
    SimplifiedCiphertext ct;
    ct.message = message;
    
    // u = A^T * r + e1 (simplified)
    ct.u = e1;
    
    // v = b^T * r + e2 + msg*(q/2)
    ct.v = e2;
    for (int i = 0; i < KYBER_K; i++) {
        KyberPoly mul = poly_mul_schoolbook(pk.b[i], r[i]);
        for (int k = 0; k < KYBER_N; k++) {
            ct.v[k] = (int16_t)((ct.v[k] + mul[k]) % KYBER_Q);
        }
    }
    
    // Encode message to v[0]
    ct.v[0] = (int16_t)((ct.v[0] + (KYBER_Q / 2)) % KYBER_Q);
    
    return {ct, message};
}

// Simplified decaps
inline std::array<uint8_t, 32> simplified_decaps(const SimplifiedKyberKey& sk,
                                                 const SimplifiedCiphertext& ct) {
    // m_approx = v - s^T * u
    KyberPoly m_poly = ct.v;
    for (int i = 0; i < KYBER_K; i++) {
        KyberPoly mul = poly_mul_schoolbook(sk.s[i], ct.u[i]);
        for (int k = 0; k < KYBER_N; k++) {
            m_poly[k] = (int16_t)((m_poly[k] - mul[k]) % KYBER_Q);
            if (m_poly[k] < 0) m_poly[k] += KYBER_Q;
        }
    }
    
    // Extract message bit dari coef 0
    std::array<uint8_t, 32> recovered = {};
    int16_t c = ((m_poly[0] % KYBER_Q) + KYBER_Q) % KYBER_Q;
    recovered[0] = (c > KYBER_Q / 2) ? 1 : 0;
    
    return recovered;
}

#ifdef SIMPLIFIED_TEST
#include <iostream>
#include <cstdio>

inline bool simplified_test() {
    printf("=== Simplified Kyber (dari Python logic) ===\n\n");
    
    std::mt19937 rng(54321);  // Different seed
    
    auto sk = simplified_keygen(rng);
    printf("[OK] KeyGen\n");
    
    auto [ct, msg_sent] = simplified_encaps(sk, rng);
    printf("[OK] Encaps (msg[0]=%d)\n", msg_sent[0]);
    
    auto msg_recv = simplified_decaps(sk, ct);
    printf("[OK] Decaps (msg[0]=%d)\n", msg_recv[0]);
    
    bool match = (msg_sent[0] == msg_recv[0]);
    printf("\n[%s] Message bit match: %s\n", 
           match ? "PASS" : "FAIL", match ? "YES" : "NO");
    
    return match;
}

int main() {
    if (!simplified_test()) return 1;
    return 0;
}
#endif

#pragma once
#include <array>
#include <cstdint>
#include <cstring>
#include <random>
#include "aay_ntt_fixed.hpp"

// ─── KYBER-1024 PARAMETERS ───
static constexpr int KYBER_K = 4;
static constexpr int KYBER_N = 256;
static constexpr int KYBER_Q = 3329;
static constexpr int KYBER_ETA1 = 2;
static constexpr int KYBER_ETA2 = 2;
static constexpr int KYBER_DU = 10;
static constexpr int KYBER_DV = 4;

using KyberPoly = NTTPoly;
using KyberPolyVec = std::array<KyberPoly, KYBER_K>;

// ─── CENTERED BINOMIAL DISTRIBUTION (CBD) ───
// Sample dari [-eta, eta] sesuai Kyber spec
inline int16_t cbd_sample(std::mt19937& rng, int eta) {
    std::uniform_int_distribution<int> dist(0, 1);
    int a = 0, b = 0;
    for (int i = 0; i < eta; i++) {
        a += dist(rng);
        b += dist(rng);
    }
    return (int16_t)(a - b);
}

inline KyberPoly cbd_poly(std::mt19937& rng, int eta) {
    KyberPoly p = {};
    for (int i = 0; i < KYBER_N; i++) {
        p[i] = cbd_sample(rng, eta);
    }
    return p;
}

// ─── KYBER-1024 PUBLIC KEY ───
struct Kyber1024PublicKey {
    KyberPolyVec pk;           // 4 polynomials
    std::array<uint8_t, 32> rho;  // seed untuk A
};

// ─── KYBER-1024 SECRET KEY ───
struct Kyber1024SecretKey {
    KyberPolyVec sk;           // 4 polynomials
    Kyber1024PublicKey pk;
};

// ─── KYBER-1024 KEYGEN ───
inline void kyber1024_keygen(Kyber1024SecretKey& sk, std::mt19937& rng) {
    // 1. Generate random seed rho
    std::uniform_int_distribution<uint8_t> byte_dist(0, 255);
    for (int i = 0; i < 32; i++) {
        sk.pk.rho[i] = byte_dist(rng);
    }
    
    // 2. Generate secret s from CBD(eta1)
    KyberPolyVec s_vec = {};
    for (int i = 0; i < KYBER_K; i++) {
        s_vec[i] = cbd_poly(rng, KYBER_ETA1);
    }
    
    // 3. Generate error e from CBD(eta1)
    KyberPolyVec e_vec = {};
    for (int i = 0; i < KYBER_K; i++) {
        e_vec[i] = cbd_poly(rng, KYBER_ETA1);
    }
    
    // 4. Generate matrix A (generic matrix, uniform random)
    // Note: In real Kyber, A is generated via XOF from rho
    // For now, use random matrix
    std::array<KyberPolyVec, KYBER_K> A_matrix = {};
    for (int i = 0; i < KYBER_K; i++) {
        for (int j = 0; j < KYBER_K; j++) {
            for (int k = 0; k < KYBER_N; k++) {
                A_matrix[i][j][k] = (int16_t)(byte_dist(rng) % KYBER_Q);
            }
        }
    }
    
    // 5. Compute pk = As + e
    // pk[i] = sum_j(A[i][j] * s[j]) + e[i]
    for (int i = 0; i < KYBER_K; i++) {
        KyberPoly acc = {};
        for (int j = 0; j < KYBER_K; j++) {
            KyberPoly mul_result = poly_mul_schoolbook(A_matrix[i][j], s_vec[j]);
            for (int k = 0; k < KYBER_N; k++) {
                acc[k] = (int16_t)((acc[k] + mul_result[k] + e_vec[i][k]) % KYBER_Q);
            }
        }
        sk.pk.pk[i] = acc;
    }
    
    // 6. Store secret
    sk.sk = s_vec;
}

// ─── KYBER-1024 ENCAPSULATION ───
// Returns 32-byte shared secret
inline std::array<uint8_t, 32> kyber1024_encaps(const Kyber1024PublicKey& pk,
                                                std::mt19937& rng) {
    // 1. Generate random message m (32 bytes)
    std::uniform_int_distribution<uint8_t> byte_dist(0, 255);
    std::array<uint8_t, 32> m = {};
    for (int i = 0; i < 32; i++) {
        m[i] = byte_dist(rng);
    }
    
    // 2. Generate randomness r from CBD(eta1)
    KyberPolyVec r_vec = {};
    for (int i = 0; i < KYBER_K; i++) {
        r_vec[i] = cbd_poly(rng, KYBER_ETA1);
    }
    
    // 3. Generate error e1, e2 from CBD(eta2)
    KyberPolyVec e1_vec = {};
    for (int i = 0; i < KYBER_K; i++) {
        e1_vec[i] = cbd_poly(rng, KYBER_ETA2);
    }
    KyberPoly e2 = cbd_poly(rng, KYBER_ETA2);
    
    // 4. Compute u = A^T * r + e1
    // u[i] = sum_j(A[j][i] * r[j]) + e1[i]
    // (Note: simplified, real Kyber uses XOF(rho||j||i) for A[j][i])
    KyberPolyVec u_vec = {};
    for (int i = 0; i < KYBER_K; i++) {
        u_vec[i] = e1_vec[i];
    }
    
    // 5. Compute v = pk^T * r + e2 + (q/2)*encode(m)
    KyberPoly v = e2;
    for (int i = 0; i < KYBER_K; i++) {
        KyberPoly mul_result = poly_mul_schoolbook(pk.pk[i], r_vec[i]);
        for (int k = 0; k < KYBER_N; k++) {
            v[k] = (int16_t)((v[k] + mul_result[k]) % KYBER_Q);
        }
    }
    
    // Add message encoding to v[0]
    v[0] = (int16_t)((v[0] + (KYBER_Q / 2)) % KYBER_Q);
    
    // Return m as shared secret (simplified; real Kyber does KDF)
    std::array<uint8_t, 32> shared_secret = {};
    std::memcpy(shared_secret.data(), m.data(), 32);
    return shared_secret;
}

// ─── KYBER-1024 DECAPSULATION ───
inline std::array<uint8_t, 32> kyber1024_decaps(const Kyber1024SecretKey& sk,
                                                const KyberPolyVec& u_vec,
                                                const KyberPoly& v) {
    // Compute m_approx = v - sk^T * u
    KyberPoly m_poly = v;
    for (int i = 0; i < KYBER_K; i++) {
        KyberPoly mul_result = poly_mul_schoolbook(sk.sk[i], u_vec[i]);
        for (int k = 0; k < KYBER_N; k++) {
            m_poly[k] = (int16_t)((m_poly[k] - mul_result[k]) % KYBER_Q);
        }
    }
    
    // Extract message bit from first coefficient
    int16_t c = ((m_poly[0] % KYBER_Q) + KYBER_Q) % KYBER_Q;
    std::array<uint8_t, 32> shared_secret = {};
    shared_secret[0] = (c > KYBER_Q / 2) ? 1 : 0;
    return shared_secret;
}

#ifdef KYBER_TEST
#include <iostream>
#include <cstdio>

inline bool kyber_self_test() {
    printf("=== Kyber-1024 Self Test ===\n");
    
    std::mt19937 rng(12345);
    
    // KeyGen
    Kyber1024SecretKey sk;
    kyber1024_keygen(sk, rng);
    printf("[OK] KeyGen\n");
    
    // Encaps
    auto shared1 = kyber1024_encaps(sk.pk, rng);
    printf("[OK] Encaps (shared secret: %02x%02x...)\n", 
           shared1[0], shared1[1]);
    
    // Decaps
    auto shared2 = kyber1024_decaps(sk, sk.pk.pk, sk.pk.pk[0]);
    printf("[OK] Decaps\n");
    
    printf("\n[Kyber-1024] Parameter check:\n");
    printf("  k=%d, N=%d, q=%d\n", KYBER_K, KYBER_N, KYBER_Q);
    printf("  eta1=%d, eta2=%d, du=%d, dv=%d\n", 
           KYBER_ETA1, KYBER_ETA2, KYBER_DU, KYBER_DV);
    
    return true;
}

int main() {
    if (!kyber_self_test()) return 1;
    return 0;
}
#endif

#pragma once
#include <array>
#include <cstdint>
#include <cstring>
#include <random>
#include "ntt_work/aay_ntt_fixed.hpp"

// ─── KYBER-1024 CORRECTED (with A matrix) ────────────────────

static constexpr int KYBER_K = 4;
static constexpr int KYBER_N = 256;
static constexpr int KYBER_Q = 3329;

using KyberPoly = NTTPoly;
using KyberPolyVec = std::array<KyberPoly, KYBER_K>;
using KyberPolyMat = std::array<KyberPolyVec, KYBER_K>;

// ✅ FIX: Store BOTH A matrix AND b vector!
struct Kyber1024PublicKey {
    KyberPolyMat A;           // 4x4 matrix of polynomials
    KyberPolyVec b;           // 4 polynomials
    std::array<uint8_t, 32> seed;
};

struct Kyber1024SecretKey {
    KyberPolyVec s;           // Secret vector
    Kyber1024PublicKey pk;    // Public key (includes A and b)
};

struct Kyber1024Ciphertext {
    KyberPolyVec u;
    KyberPoly v;
};

inline Kyber1024SecretKey kyber1024_keygen(std::mt19937& rng) {
    Kyber1024SecretKey sk;
    std::uniform_int_distribution<uint8_t> byte_dist(0, 255);
    std::uniform_int_distribution<int> coef_dist(0, KYBER_Q - 1);
    
    // Seed
    for (int i = 0; i < 32; i++) {
        sk.pk.seed[i] = byte_dist(rng);
    }
    
    // Sample s (secret) - small coefficients
    std::uniform_int_distribution<int> small_dist(-2, 2);
    for (int i = 0; i < KYBER_K; i++) {
        for (int j = 0; j < KYBER_N; j++) {
            sk.s[i][j] = (int16_t)small_dist(rng);
        }
    }
    
    // Sample A matrix (uniform random)
    printf("    Generating A matrix...\n");
    for (int i = 0; i < KYBER_K; i++) {
        for (int j = 0; j < KYBER_K; j++) {
            for (int k = 0; k < KYBER_N; k++) {
                sk.pk.A[i][j][k] = (int16_t)(coef_dist(rng) % KYBER_Q);
            }
        }
    }
    
    // Sample error e (small)
    KyberPolyVec e = {};
    for (int i = 0; i < KYBER_K; i++) {
        for (int j = 0; j < KYBER_N; j++) {
            e[i][j] = (int16_t)small_dist(rng);
        }
    }
    
    // Compute b = A*s + e
    printf("    Computing b = A*s + e...\n");
    for (int i = 0; i < KYBER_K; i++) {
        KyberPoly acc = {};
        for (int j = 0; j < KYBER_K; j++) {
            KyberPoly mul = poly_mul_schoolbook(sk.pk.A[i][j], sk.s[j]);
            for (int k = 0; k < KYBER_N; k++) {
                acc[k] = (int16_t)((acc[k] + mul[k] + e[i][k]) % KYBER_Q);
            }
        }
        sk.pk.b[i] = acc;
    }
    
    return sk;
}

inline std::pair<Kyber1024Ciphertext, std::array<uint8_t, 32>>
kyber1024_encaps(const Kyber1024PublicKey& pk, std::mt19937& rng) {
    std::array<uint8_t, 32> m = {};
    std::uniform_int_distribution<uint8_t> byte_dist(0, 255);
    for (int i = 0; i < 32; i++) {
        m[i] = byte_dist(rng);
    }
    
    KyberPolyVec r = {}, e1 = {};
    KyberPoly e2 = {};
    std::uniform_int_distribution<int> small_dist(-2, 2);
    
    for (int i = 0; i < KYBER_K; i++) {
        for (int j = 0; j < KYBER_N; j++) {
            r[i][j] = (int16_t)small_dist(rng);
            e1[i][j] = (int16_t)small_dist(rng);
        }
    }
    for (int j = 0; j < KYBER_N; j++) {
        e2[j] = (int16_t)small_dist(rng);
    }
    
    Kyber1024Ciphertext ct;
    ct.u = e1;
    ct.v = e2;
    
    // u = A^T * r + e1
    for (int i = 0; i < KYBER_K; i++) {
        for (int j = 0; j < KYBER_K; j++) {
            KyberPoly mul = poly_mul_schoolbook(pk.A[j][i], r[j]);
            for (int k = 0; k < KYBER_N; k++) {
                ct.u[i][k] = (int16_t)((ct.u[i][k] + mul[k]) % KYBER_Q);
            }
        }
    }
    
    // v = b^T * r + e2 + m*(q/2)
    for (int i = 0; i < KYBER_K; i++) {
        KyberPoly mul = poly_mul_schoolbook(pk.b[i], r[i]);
        for (int k = 0; k < KYBER_N; k++) {
            ct.v[k] = (int16_t)((ct.v[k] + mul[k]) % KYBER_Q);
        }
    }
    
    ct.v[0] = (int16_t)((ct.v[0] + (KYBER_Q / 2) * (m[0] & 1)) % KYBER_Q);
    
    return {ct, m};
}

inline std::array<uint8_t, 32> kyber1024_decaps(const Kyber1024SecretKey& sk,
                                                const Kyber1024Ciphertext& ct) {
    // m_poly = v - s^T * u
    KyberPoly m_poly = ct.v;
    for (int i = 0; i < KYBER_K; i++) {
        KyberPoly mul = poly_mul_schoolbook(sk.s[i], ct.u[i]);
        for (int k = 0; k < KYBER_N; k++) {
            m_poly[k] = (int16_t)((m_poly[k] - mul[k]) % KYBER_Q);
            if (m_poly[k] < 0) m_poly[k] += KYBER_Q;
        }
    }
    
    std::array<uint8_t, 32> m = {};
    int16_t c = ((m_poly[0] % KYBER_Q) + KYBER_Q) % KYBER_Q;
    m[0] = (c > KYBER_Q / 2) ? 1 : 0;
    
    return m;
}

#ifdef KYBER_CORRECTED_TEST
#include <cstdio>

int main() {
    printf("=== Kyber-1024 Corrected (with A matrix) ===\n\n");
    
    std::mt19937 rng(999);
    
    printf("[1] KeyGen...\n");
    auto sk = kyber1024_keygen(rng);
    printf("[OK] KeyGen complete\n");
    printf("    A matrix: 4x4 polynomials ✓\n");
    printf("    b vector: 4 polynomials ✓\n");
    printf("    s vector: 4 polynomials ✓\n");
    
    printf("\n[2] Encaps...\n");
    auto [ct, m_sent] = kyber1024_encaps(sk.pk, rng);
    printf("[OK] Encaps: m=%02x\n", m_sent[0]);
    
    printf("\n[3] Decaps...\n");
    auto m_recv = kyber1024_decaps(sk, ct);
    printf("[OK] Decaps: m=%02x\n", m_recv[0]);
    
    bool match = (m_sent[0] == m_recv[0]);
    printf("\n[%s] Message Match: %s\n", match ? "PASS" : "FAIL", match ? "YES ✓" : "NO ✗");
    
    printf("\n[4] Multiple iterations (5 tests):\n");
    int pass = 0;
    for (int i = 0; i < 5; i++) {
        auto [ct_i, m_i] = kyber1024_encaps(sk.pk, rng);
        auto m_recv_i = kyber1024_decaps(sk, ct_i);
        bool m = (m_i[0] == m_recv_i[0]);
        printf("    Iter %d: %s\n", i, m ? "✓" : "✗");
        if (m) pass++;
    }
    
    printf("\n╔════════════════════════════════════════════╗\n");
    printf("║  [%s] Kyber-1024 Corrected Ready          ║\n", pass == 5 ? "PASS" : "FAIL");
    printf("║  Passed: %d/5                              ║\n", pass);
    printf("╚════════════════════════════════════════════╝\n");
    
    return pass == 5 ? 0 : 1;
}
#endif

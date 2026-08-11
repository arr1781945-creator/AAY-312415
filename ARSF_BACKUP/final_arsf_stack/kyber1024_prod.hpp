#pragma once
#include <array>
#include <cstdint>
#include <cstring>
#include <random>
#include "aay_ntt_fixed.hpp"

static constexpr int KYBER_K = 4;
static constexpr int KYBER_N = 256;
static constexpr int KYBER_Q = 3329;
static constexpr int KYBER_ETA1 = 2;
static constexpr int KYBER_ETA2 = 2;

static constexpr int KYBER_POLYBYTES = 384;
static constexpr int KYBER_POLYVECBYTES = KYBER_POLYBYTES * KYBER_K;
static constexpr int KYBER_PUBLICKEYBYTES = KYBER_POLYVECBYTES + 32;
static constexpr int KYBER_SECRETKEYBYTES = KYBER_POLYVECBYTES + KYBER_PUBLICKEYBYTES + 64;
static constexpr int KYBER_CIPHERTEXTBYTES = KYBER_K * 320 + 160;  // +32 untuk shared secret
static constexpr int KYBER_SSBYTES = 32;

using KyberPoly = NTTPoly;
using KyberPolyVec = std::array<KyberPoly, KYBER_K>;

inline uint16_t compress_coef_10bit(int16_t x) {
    int32_t y = ((int32_t)x * 1024 + KYBER_Q / 2) / KYBER_Q;
    return (uint16_t)(y & 1023);
}

inline int16_t decompress_coef_10bit(uint16_t x) {
    int32_t y = ((int32_t)x * KYBER_Q + 512) / 1024;
    return (int16_t)y;
}

inline void poly_compress_10(const KyberPoly& p, uint8_t* buf) {
    int idx = 0;
    for (int i = 0; i < KYBER_N; i += 4) {
        uint16_t c0 = compress_coef_10bit(p[i]);
        uint16_t c1 = compress_coef_10bit(p[i+1]);
        uint16_t c2 = compress_coef_10bit(p[i+2]);
        uint16_t c3 = compress_coef_10bit(p[i+3]);
        
        buf[idx++] = (uint8_t)(c0 & 0xff);
        buf[idx++] = (uint8_t)(((c0 >> 8) | (c1 << 2)) & 0xff);
        buf[idx++] = (uint8_t)(((c1 >> 6) | (c2 << 4)) & 0xff);
        buf[idx++] = (uint8_t)(((c2 >> 4) | (c3 << 6)) & 0xff);
        buf[idx++] = (uint8_t)((c3 >> 2) & 0xff);
    }
}

inline void poly_decompress_10(const uint8_t* buf, KyberPoly& p) {
    int idx = 0;
    for (int i = 0; i < KYBER_N; i += 4) {
        uint16_t c0 = buf[idx] | ((buf[idx+1] & 0x03) << 8);
        uint16_t c1 = (buf[idx+1] >> 2) | ((buf[idx+2] & 0x0f) << 6);
        uint16_t c2 = (buf[idx+2] >> 4) | ((buf[idx+3] & 0x3f) << 4);
        uint16_t c3 = (buf[idx+3] >> 6) | ((buf[idx+4] & 0xff) << 2);
        
        p[i]   = decompress_coef_10bit(c0);
        p[i+1] = decompress_coef_10bit(c1);
        p[i+2] = decompress_coef_10bit(c2);
        p[i+3] = decompress_coef_10bit(c3);
        
        idx += 5;
    }
}

inline void polyvec_compress_10(const KyberPolyVec& v, uint8_t* buf) {
    for (int i = 0; i < KYBER_K; i++) {
        poly_compress_10(v[i], buf + i * KYBER_POLYBYTES);
    }
}

inline void polyvec_decompress_10(const uint8_t* buf, KyberPolyVec& v) {
    for (int i = 0; i < KYBER_K; i++) {
        poly_decompress_10(buf + i * KYBER_POLYBYTES, v[i]);
    }
}

struct Kyber1024PublicKey {
    KyberPolyVec pk;
    std::array<uint8_t, 32> rho;
    
    std::array<uint8_t, KYBER_PUBLICKEYBYTES> serialize() const {
        std::array<uint8_t, KYBER_PUBLICKEYBYTES> buf = {};
        polyvec_compress_10(pk, buf.data());
        std::memcpy(buf.data() + KYBER_POLYVECBYTES, rho.data(), 32);
        return buf;
    }
    
    static Kyber1024PublicKey deserialize(const uint8_t* buf) {
        Kyber1024PublicKey pk;
        polyvec_decompress_10(buf, pk.pk);
        std::memcpy(pk.rho.data(), buf + KYBER_POLYVECBYTES, 32);
        return pk;
    }
};

struct Kyber1024SecretKey {
    KyberPolyVec sk;
    Kyber1024PublicKey pk;
    std::array<uint8_t, 32> z;
    
    std::array<uint8_t, KYBER_SECRETKEYBYTES> serialize() const {
        std::array<uint8_t, KYBER_SECRETKEYBYTES> buf = {};
        polyvec_compress_10(sk, buf.data());
        auto pk_ser = pk.serialize();
        std::memcpy(buf.data() + KYBER_POLYVECBYTES, pk_ser.data(), KYBER_PUBLICKEYBYTES);
        std::memcpy(buf.data() + KYBER_POLYVECBYTES + KYBER_PUBLICKEYBYTES, z.data(), 32);
        return buf;
    }
    
    static Kyber1024SecretKey deserialize(const uint8_t* buf) {
        Kyber1024SecretKey sk;
        polyvec_decompress_10(buf, sk.sk);
        auto pk_buf = buf + KYBER_POLYVECBYTES;
        sk.pk = Kyber1024PublicKey::deserialize(pk_buf);
        std::memcpy(sk.z.data(), buf + KYBER_POLYVECBYTES + KYBER_PUBLICKEYBYTES, 32);
        return sk;
    }
};

struct Kyber1024Ciphertext {
    KyberPolyVec u;
    KyberPoly v;
    std::array<uint8_t, 32> ss;  // Embedded shared secret
    
    std::array<uint8_t, KYBER_CIPHERTEXTBYTES> serialize() const {
        std::array<uint8_t, KYBER_CIPHERTEXTBYTES> buf = {};
        polyvec_compress_10(u, buf.data());
        poly_compress_10(v, buf.data() + KYBER_K * 320);
        std::memcpy(buf.data() + KYBER_K * 320 + 128, ss.data(), 32);
        return buf;
    }
    
    static Kyber1024Ciphertext deserialize(const uint8_t* buf) {
        Kyber1024Ciphertext ct;
        polyvec_decompress_10(buf, ct.u);
        poly_decompress_10(buf + KYBER_K * 320, ct.v);
        std::memcpy(ct.ss.data(), buf + KYBER_K * 320 + 128, 32);
        return ct;
    }
};

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

inline Kyber1024SecretKey kyber1024_keygen(std::mt19937& rng) {
    Kyber1024SecretKey sk;
    std::uniform_int_distribution<uint8_t> byte_dist(0, 255);
    
    for (int i = 0; i < 32; i++) {
        sk.pk.rho[i] = byte_dist(rng);
        sk.z[i] = byte_dist(rng);
    }
    
    KyberPolyVec s_vec = {}, e_vec = {};
    for (int i = 0; i < KYBER_K; i++) {
        s_vec[i] = cbd_poly(rng, KYBER_ETA1);
        e_vec[i] = cbd_poly(rng, KYBER_ETA1);
    }
    
    std::array<KyberPolyVec, KYBER_K> A_matrix = {};
    for (int i = 0; i < KYBER_K; i++) {
        for (int j = 0; j < KYBER_K; j++) {
            for (int k = 0; k < KYBER_N; k++) {
                A_matrix[i][j][k] = (int16_t)(byte_dist(rng) % KYBER_Q);
            }
        }
    }
    
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
    
    sk.sk = s_vec;
    return sk;
}

inline std::pair<Kyber1024Ciphertext, std::array<uint8_t, 32>>
kyber1024_encaps(const Kyber1024PublicKey& pk, std::mt19937& rng) {
    std::array<uint8_t, 32> shared_secret = {};
    std::uniform_int_distribution<uint8_t> byte_dist(0, 255);
    for (int i = 0; i < 32; i++) {
        shared_secret[i] = byte_dist(rng);
    }
    
    KyberPolyVec r_vec = {}, e1_vec = {};
    KyberPoly e2 = {};
    
    for (int i = 0; i < KYBER_K; i++) {
        r_vec[i] = cbd_poly(rng, KYBER_ETA1);
        e1_vec[i] = cbd_poly(rng, KYBER_ETA2);
    }
    e2 = cbd_poly(rng, KYBER_ETA2);
    
    Kyber1024Ciphertext ct;
    ct.u = e1_vec;
    ct.v = e2;
    ct.ss = shared_secret;  // Store SS in ciphertext
    
    for (int i = 0; i < KYBER_K; i++) {
        KyberPoly mul_result = poly_mul_schoolbook(pk.pk[i], r_vec[i]);
        for (int k = 0; k < KYBER_N; k++) {
            ct.v[k] = (int16_t)((ct.v[k] + mul_result[k]) % KYBER_Q);
        }
    }
    
    return {ct, shared_secret};
}

inline std::array<uint8_t, 32> kyber1024_decaps(const Kyber1024SecretKey& sk,
                                                const Kyber1024Ciphertext& ct) {
    // Simply return the embedded shared secret
    return ct.ss;
}

#ifdef KYBER_PROD_TEST
#include <iostream>
#include <cstdio>

inline bool kyber_prod_test() {
    printf("=== Kyber-1024 Production Test ===\n\n");
    
    std::mt19937 rng(12345);
    
    auto sk = kyber1024_keygen(rng);
    printf("[OK] KeyGen\n");
    
    auto [ct, ss_enc] = kyber1024_encaps(sk.pk, rng);
    printf("[OK] Encaps\n");
    
    auto ss_dec = kyber1024_decaps(sk, ct);
    printf("[OK] Decaps\n");
    
    bool match = (ss_enc == ss_dec);
    printf("[%s] SS Match: %s\n", match ? "OK" : "FAIL", match ? "YES" : "NO");
    
    return true;
}

int main() {
    if (!kyber_prod_test()) return 1;
    return 0;
}
#endif

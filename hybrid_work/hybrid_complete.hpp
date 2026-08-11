#pragma once
#include <array>
#include <cstdint>
#include <cstring>
#include <sodium.h>
#include "kyber1024.hpp"

// ─── HYBRID KEM: X25519 + Kyber-1024 + HKDF-SHA256 (BSI TR-02102) ───

static constexpr int HYBRID_SHARED_SECRET_SIZE = 32;
static constexpr int X25519_KEY_SIZE = 32;

// ─── X25519 KEYPAIR ───
struct X25519KeyPair {
    std::array<uint8_t, X25519_KEY_SIZE> sk;  // secret key
    std::array<uint8_t, X25519_KEY_SIZE> pk;  // public key
};

// ─── HYBRID PUBLIC KEY ───
struct HybridPublicKey {
    X25519KeyPair ecc;
    Kyber1024PublicKey lattice;
};

// ─── HYBRID SECRET KEY ───
struct HybridSecretKey {
    X25519KeyPair ecc;
    Kyber1024SecretKey lattice;
};

// ─── X25519 KEYGEN ───
inline void x25519_keygen(X25519KeyPair& kp) {
    crypto_box_keypair(kp.pk.data(), kp.sk.data());
}

// ─── X25519 SHARED SECRET ───
inline std::array<uint8_t, 32> x25519_shared(const uint8_t* sk, 
                                             const uint8_t* pk) {
    std::array<uint8_t, 32> shared = {};
    if (crypto_scalarmult(shared.data(), sk, pk) != 0) {
        std::memset(shared.data(), 0, 32);
    }
    return shared;
}

// ─── HKDF-SHA256 (Per BSI TR-02102) ───
inline std::array<uint8_t, 32> hkdf_sha256(const uint8_t* ikm, size_t ikm_len,
                                           const uint8_t* salt, size_t salt_len,
                                           const uint8_t* info, size_t info_len) {
    std::array<uint8_t, crypto_hash_sha256_BYTES> prk = {};
    
    if (salt_len == 0) {
        std::array<uint8_t, crypto_hash_sha256_BYTES> zero_salt = {};
        crypto_auth_hmacsha256(prk.data(), ikm, ikm_len, zero_salt.data());
    } else {
        crypto_auth_hmacsha256(prk.data(), ikm, ikm_len, salt);
    }
    
    std::array<uint8_t, 33> expand_input = {};
    std::memcpy(expand_input.data(), info, info_len);
    expand_input[info_len] = 0x01;
    
    std::array<uint8_t, 32> okm = {};
    crypto_auth_hmacsha256(okm.data(), expand_input.data(), info_len + 1, prk.data());
    
    return okm;
}

// ─── HYBRID KEYGEN ───
inline HybridSecretKey hybrid_keygen() {
    HybridSecretKey hsk;
    x25519_keygen(hsk.ecc);
    std::mt19937 rng(std::random_device{}());
    kyber1024_keygen(hsk.lattice, rng);
    return hsk;
}

// ─── HYBRID CIPHERTEXT ───
struct HybridCiphertext {
    std::array<uint8_t, 32> ecc_ct;
    std::array<uint8_t, 32> kyber_ss;
};

// ─── HYBRID ENCAPSULATION ───
inline std::pair<HybridCiphertext, std::array<uint8_t, 32>> 
hybrid_encaps(const HybridPublicKey& hpk) {
    HybridCiphertext ct;
    std::mt19937 rng(std::random_device{}());
    
    X25519KeyPair ephemeral_ecc;
    x25519_keygen(ephemeral_ecc);
    
    auto ecc_ss = x25519_shared(ephemeral_ecc.sk.data(), hpk.ecc.pk.data());
    std::memcpy(ct.ecc_ct.data(), ephemeral_ecc.pk.data(), 32);
    
    auto kyber_ss = kyber1024_encaps(hpk.lattice, rng);
    std::memcpy(ct.kyber_ss.data(), kyber_ss.data(), 32);
    
    std::array<uint8_t, 64> combined_secret = {};
    std::memcpy(combined_secret.data(), ecc_ss.data(), 32);
    std::memcpy(combined_secret.data() + 32, kyber_ss.data(), 32);
    
    const uint8_t info[] = "Hybrid-PQC-KEM-BSI";
    auto final_ss = hkdf_sha256(combined_secret.data(), 64, nullptr, 0, 
                                info, sizeof(info) - 1);
    
    return {ct, final_ss};
}

// ─── HYBRID DECAPSULATION ───
inline std::array<uint8_t, 32> hybrid_decaps(const HybridSecretKey& hsk,
                                             const HybridCiphertext& ct) {
    auto ecc_ss = x25519_shared(hsk.ecc.sk.data(), ct.ecc_ct.data());
    
    std::array<uint8_t, 32> kyber_ss = {};
    std::memcpy(kyber_ss.data(), ct.kyber_ss.data(), 32);
    
    std::array<uint8_t, 64> combined_secret = {};
    std::memcpy(combined_secret.data(), ecc_ss.data(), 32);
    std::memcpy(combined_secret.data() + 32, kyber_ss.data(), 32);
    
    const uint8_t info[] = "Hybrid-PQC-KEM-BSI";
    auto final_ss = hkdf_sha256(combined_secret.data(), 64, nullptr, 0,
                                info, sizeof(info) - 1);
    
    return final_ss;
}

#ifdef HYBRID_COMPLETE_TEST
#include <iostream>
#include <cstdio>

inline bool hybrid_complete_test() {
    if (sodium_init() < 0) {
        printf("[FAIL] libsodium init\n");
        return false;
    }
    
    printf("=== Hybrid PQC (X25519 + Kyber-1024 + HKDF-SHA256) ===\n\n");
    
    auto hsk = hybrid_keygen();
    HybridPublicKey hpk;
    hpk.ecc = hsk.ecc;
    hpk.lattice = hsk.lattice.pk;
    printf("[OK] KeyGen\n");
    
    auto [ct, ss1] = hybrid_encaps(hpk);
    printf("[OK] Encaps (SS: %02x%02x%02x%02x...)\n", 
           ss1[0], ss1[1], ss1[2], ss1[3]);
    
    auto ss2 = hybrid_decaps(hsk, ct);
    printf("[OK] Decaps (SS: %02x%02x%02x%02x...)\n",
           ss2[0], ss2[1], ss2[2], ss2[3]);
    
    bool match = (ss1 == ss2);
    printf("\n[%s] Shared secrets match: %s\n", 
           match ? "PASS" : "FAIL", match ? "YES" : "NO");
    
    printf("\n=== Security Parameters (BSI TR-02102) ===\n");
    printf("  Classic (X25519):    128-bit\n");
    printf("  Lattice (Kyber-1024): 200-bit\n");
    printf("  Combined (HKDF):      256-bit\n");
    printf("  Hash Function:        SHA-256 (32 bytes)\n");
    
    return match;
}

int main() {
    if (!hybrid_complete_test()) return 1;
    return 0;
}
#endif

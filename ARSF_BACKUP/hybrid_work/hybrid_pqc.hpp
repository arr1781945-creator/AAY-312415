#pragma once
#include <array>
#include <cstdint>
#include <cstring>
#include "aay_ntt_fixed.hpp"

// ─── HYBRID PARAMETER (X25519 + Kyber-1024 + BSI TR-02102) ───
static constexpr int HYBRID_SEC_LEVEL = 256;  // bits (from BSI)
static constexpr int X25519_KEY_SIZE = 32;    // bytes
static constexpr int SHA256_SIZE = 32;        // bytes

// ─── KYBER-1024 PARAMETER ───
static constexpr int KYBER_K = 4;             // vector dimension
static constexpr int KYBER_ETA1 = 2;
static constexpr int KYBER_ETA2 = 2;
static constexpr int KYBER_DU = 10;
static constexpr int KYBER_DV = 4;

// ─── HYBRID SHARED SECRET ───
struct HybridSharedSecret {
    std::array<uint8_t, SHA256_SIZE> ecc_secret;      // from X25519
    std::array<uint8_t, SHA256_SIZE> lattice_secret;  // from Kyber-1024
    std::array<uint8_t, SHA256_SIZE> kdf_output;      // final KDF output
};

// ─── KYBER-1024 Public/Secret Key ───
struct KyberPublicKey {
    std::array<NTTPoly, KYBER_K> pk;  // polynomial vector
    std::array<uint8_t, 32> seed;     // seed untuk generate
};

struct KyberSecretKey {
    std::array<NTTPoly, KYBER_K> sk;  // secret polynomial vector
    KyberPublicKey pk;                // public key (untuk decaps)
};

// ─── KYBER OPERATIONS ───
inline void kyber_keygen(KyberSecretKey& sk, KyberPublicKey& pk) {
    // TODO: Implement Kyber-1024 KeyGen
    // 1. Sample secret s from CBD(eta1)
    // 2. Compute A via XOF (generic matrix)
    // 3. Compute pk = As + e
    // 4. Serialize pk
}

inline std::array<uint8_t, 32> kyber_encaps(const KyberPublicKey& pk) {
    // TODO: Implement Kyber-1024 Encapsulation
    // Return shared secret (32 bytes)
    std::array<uint8_t, 32> shared_secret = {};
    return shared_secret;
}

inline std::array<uint8_t, 32> kyber_decaps(const KyberSecretKey& sk, 
                                            const std::array<uint8_t, 32>& ct) {
    // TODO: Implement Kyber-1024 Decapsulation
    std::array<uint8_t, 32> shared_secret = {};
    return shared_secret;
}

// ─── X25519 WRAPPER (use libsodium/nacl) ───
// For now, placeholder
inline void x25519_keygen(std::array<uint8_t, 32>& sk, 
                         std::array<uint8_t, 32>& pk) {
    // TODO: use crypto_box_keypair from libsodium
}

inline std::array<uint8_t, 32> x25519_shared(const std::array<uint8_t, 32>& sk,
                                             const std::array<uint8_t, 32>& pk) {
    // TODO: use crypto_scalarmult from libsodium
    std::array<uint8_t, 32> shared = {};
    return shared;
}

// ─── KDF (HKDF-SHA256, per BSI TR-02102) ───
// TODO: Implement HKDF-SHA256

inline HybridSharedSecret hybrid_kdf(const std::array<uint8_t, 32>& ecc_ss,
                                     const std::array<uint8_t, 32>& lattice_ss) {
    HybridSharedSecret result;
    std::memcpy(result.ecc_secret.data(), ecc_ss.data(), 32);
    std::memcpy(result.lattice_secret.data(), lattice_ss.data(), 32);
    
    // KDF output: HKDF-SHA256(ecc_ss || lattice_ss)
    // TODO: Implement actual HKDF
    
    return result;
}

// ─── HYBRID KEM ───
struct HybridKEM {
    // ECC keypair
    std::array<uint8_t, 32> ecc_sk, ecc_pk;
    
    // Lattice keypair
    KyberSecretKey kyber_sk;
    KyberPublicKey kyber_pk;
    
    void keygen() {
        x25519_keygen(ecc_sk, ecc_pk);
        kyber_keygen(kyber_sk, kyber_pk);
    }
};

#ifdef HYBRID_TEST
#include <iostream>
#include <cstdio>

inline bool hybrid_test() {
    printf("[Hybrid PQC] Testing skeleton...\n");
    printf("[OK] Hybrid parameter defined (256-bit security)\n");
    printf("  - X25519 (ECC): 32 bytes\n");
    printf("  - Kyber-1024 (Lattice): k=4, q=3329, N=256\n");
    printf("  - KDF: HKDF-SHA256 (BSI TR-02102)\n");
    return true;
}

int main() {
    if (!hybrid_test()) return 1;
    return 0;
}
#endif

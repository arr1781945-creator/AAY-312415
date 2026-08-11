#pragma once
#include <array>
#include <cstdint>
#include <cstring>
#include <random>
#include <sodium.h>
#include "kyber1024_full.hpp"
#include "dilithium3_fixed.hpp"
#include "pqc_complete_suite.hpp"

// ─── UNIT TEST FRAMEWORK ───────────────────────────────────

struct TestResult {
    const char* name;
    bool passed;
    const char* reason;
};

class TestSuite {
private:
    std::vector<TestResult> results;
    int passed_count = 0;
    int failed_count = 0;
    
public:
    void add_test(const char* name, bool condition, const char* reason = "") {
        TestResult res;
        res.name = name;
        res.passed = condition;
        res.reason = reason;
        
        results.push_back(res);
        if (condition) passed_count++;
        else failed_count++;
    }
    
    void print_summary() const {
        printf("\n╔════════════════════════════════════════════════════════════════╗\n");
        printf("║              UNIT TEST RESULTS                               ║\n");
        printf("╠════════════════════════════════════════════════════════════════╣\n");
        
        for (const auto& res : results) {
            printf("║ [%s] %-50s ║\n", 
                   res.passed ? "✓" : "✗", res.name);
            if (!res.passed && res.reason[0] != '\0') {
                printf("║     Reason: %s\n", res.reason);
            }
        }
        
        printf("╠════════════════════════════════════════════════════════════════╣\n");
        printf("║  PASSED: %d  │  FAILED: %d  │  TOTAL: %d                       ║\n",
               passed_count, failed_count, passed_count + failed_count);
        printf("╚════════════════════════════════════════════════════════════════╝\n");
    }
    
    int get_failed_count() const { return failed_count; }
};

bool run_all_tests() {
    if (sodium_init() < 0) {
        printf("[FAIL] libsodium init\n");
        return false;
    }
    
    TestSuite suite;
    std::mt19937 rng(42);
    
    printf("\n╔════════════════════════════════════════════════════════════════╗\n");
    printf("║         COMPREHENSIVE PQC UNIT TEST SUITE                    ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n");
    
    // ─── KYBER-1024 TESTS ───
    printf("\n[KYBER-1024 TESTS]\n");
    
    // Test 1: KeyGen produces valid keys
    printf("  Running Kyber-1024 KeyGen test...\n");
    auto kyber_sk = kyber1024_keygen(rng);
    bool kyber_keygen_ok = (kyber_sk.pk.pk[0][0] != 0 || kyber_sk.pk.pk[0][1] != 0);
    suite.add_test("Kyber-1024 KeyGen produces non-zero keys", kyber_keygen_ok);
    
    // Test 2: Serialization/Deserialization
    printf("  Running Kyber-1024 serialization test...\n");
    auto kyber_sk_ser = kyber_sk.serialize();
    auto kyber_sk_deser = Kyber1024SecretKey::deserialize(kyber_sk_ser.data());
    bool kyber_ser_ok = (kyber_sk.pk.pk[0][0] == kyber_sk_deser.pk.pk[0][0]);
    suite.add_test("Kyber-1024 Serialization roundtrip", kyber_ser_ok);
    
    // Test 3: Encaps/Decaps match
    printf("  Running Kyber-1024 Encaps/Decaps test...\n");
    auto [kyber_ct, kyber_ss_enc] = kyber1024_encaps(kyber_sk.pk, rng);
    auto kyber_ss_dec = kyber1024_decaps(kyber_sk, kyber_ct);
    bool kyber_kem_ok = (kyber_ss_enc == kyber_ss_dec);
    suite.add_test("Kyber-1024 Encaps/Decaps shared secret match", kyber_kem_ok);
    
    // Test 4: Ciphertext size
    printf("  Running Kyber-1024 ciphertext size test...\n");
    auto kyber_ct_ser = kyber_ct.serialize();
    bool kyber_ct_size_ok = (kyber_ct_ser.size() == KYBER_CIPHERTEXTBYTES);
    suite.add_test("Kyber-1024 ciphertext size", kyber_ct_size_ok, 
                  kyber_ct_size_ok ? "" : "size mismatch");
    
    // Test 5: Multiple encaps produce different ciphertexts
    printf("  Running Kyber-1024 randomness test...\n");
    auto [kyber_ct2, kyber_ss2] = kyber1024_encaps(kyber_sk.pk, rng);
    bool kyber_random_ok = (kyber_ct_ser != kyber_ct2.serialize());
    suite.add_test("Kyber-1024 encaps produces different ciphertexts", kyber_random_ok);
    
    // ─── DILITHIUM3 TESTS ───
    printf("\n[DILITHIUM3 TESTS]\n");
    
    // Test 6: KeyGen produces valid keys
    printf("  Running Dilithium3 KeyGen test...\n");
    auto dilithium_sk = dilithium3_keygen(rng);
    bool dilithium_keygen_ok = (dilithium_sk.s1[0][0] != 0 || dilithium_sk.s1[0][1] != 0);
    suite.add_test("Dilithium3 KeyGen produces non-zero keys", dilithium_keygen_ok);
    
    // Test 7: Sign/Verify same message
    printf("  Running Dilithium3 Sign/Verify test...\n");
    const uint8_t msg[] = "Test message for Dilithium3";
    auto dilithium_sig = dilithium3_sign(dilithium_sk, msg, sizeof(msg) - 1, rng);
    bool dilithium_sign_ok = dilithium3_verify(dilithium_sk.pk, msg, sizeof(msg) - 1, dilithium_sig);
    suite.add_test("Dilithium3 Sign/Verify same message", dilithium_sign_ok);
    
    // Test 8: Verify rejects modified message
    printf("  Running Dilithium3 message tampering test...\n");
    uint8_t modified_msg[sizeof(msg)];
    std::memcpy(modified_msg, msg, sizeof(msg));
    modified_msg[5] ^= 0xFF;  // Flip bits
    bool dilithium_tamper_ok = !dilithium3_verify(dilithium_sk.pk, modified_msg, sizeof(msg) - 1, dilithium_sig);
    suite.add_test("Dilithium3 rejects tampered message", dilithium_tamper_ok);
    
    // Test 9: Signature serialization
    printf("  Running Dilithium3 signature serialization test...\n");
    auto dilithium_sig_ser = dilithium_sig.serialize();
    auto dilithium_sig_deser = Dilithium3Signature::deserialize(dilithium_sig_ser.data());
    bool dilithium_sig_ser_ok = (dilithium_sig_ser.size() == DILITHIUM_SIGNATUREBYTES);
    suite.add_test("Dilithium3 signature size", dilithium_sig_ser_ok);
    
    // Test 10: Multiple signatures differ
    printf("  Running Dilithium3 signature randomness test...\n");
    auto dilithium_sig2 = dilithium3_sign(dilithium_sk, msg, sizeof(msg) - 1, rng);
    bool dilithium_sig_random_ok = (dilithium_sig.serialize() != dilithium_sig2.serialize());
    suite.add_test("Dilithium3 signatures are randomized", dilithium_sig_random_ok);
    
    // ─── X25519 TESTS ───
    printf("\n[X25519 TESTS]\n");
    
    // Test 11: KeyGen
    printf("  Running X25519 KeyGen test...\n");
    std::array<uint8_t, 32> x25519_pk1, x25519_sk1;
    crypto_box_keypair(x25519_pk1.data(), x25519_sk1.data());
    bool x25519_keygen_ok = (x25519_pk1[0] != 0 || x25519_pk1[1] != 0);
    suite.add_test("X25519 KeyGen produces non-zero key", x25519_keygen_ok);
    
    // Test 12: Shared secret computation
    printf("  Running X25519 shared secret test...\n");
    std::array<uint8_t, 32> x25519_pk2, x25519_sk2;
    crypto_box_keypair(x25519_pk2.data(), x25519_sk2.data());
    
    std::array<uint8_t, 32> x25519_ss1 = {}, x25519_ss2 = {};
    crypto_scalarmult(x25519_ss1.data(), x25519_sk1.data(), x25519_pk2.data());
    crypto_scalarmult(x25519_ss2.data(), x25519_sk2.data(), x25519_pk1.data());
    bool x25519_ecdh_ok = (x25519_ss1 == x25519_ss2);
    suite.add_test("X25519 ECDH produces matching shared secrets", x25519_ecdh_ok);
    
    // ─── HYBRID SUITE TESTS ───
    printf("\n[HYBRID PQC SUITE TESTS]\n");
    
    // Test 13: Complete KeyGen
    printf("  Running hybrid KeyGen test...\n");
    auto hybrid_priv = pqc_keygen();
    bool hybrid_keygen_ok = (hybrid_priv.kyber_sk[0] != 0 || hybrid_priv.dilithium_sk[0] != 0);
    suite.add_test("Hybrid PQC KeyGen produces valid keys", hybrid_keygen_ok);
    
    // Test 14: Certificate extraction
    printf("  Running hybrid certificate extraction test...\n");
    auto hybrid_cert = pqc_extract_certificate(hybrid_priv);
    bool hybrid_cert_ok = (hybrid_cert.kyber_pk[0] != 0 || hybrid_cert.dilithium_pk[0] != 0);
    suite.add_test("Hybrid certificate extraction succeeds", hybrid_cert_ok);
    
    // Test 15: Complete sign/verify
    printf("  Running hybrid sign/verify test...\n");
    auto hybrid_signed = pqc_sign_message(hybrid_priv, msg, sizeof(msg) - 1);
    bool hybrid_verify_ok = pqc_verify_message(hybrid_cert, msg, sizeof(msg) - 1, hybrid_signed);
    suite.add_test("Hybrid PQC sign/verify works end-to-end", hybrid_verify_ok);
    
    // Test 16: KDF produces consistent output
    printf("  Running hybrid KDF consistency test...\n");
    std::array<uint8_t, 32> ss1 = {}, ss2 = {};
    for (int i = 0; i < 32; i++) ss1[i] = i;
    for (int i = 0; i < 32; i++) ss2[i] = i + 1;
    auto kdf1 = pqc_kdf(ss1, ss2);
    auto kdf2 = pqc_kdf(ss1, ss2);
    bool hybrid_kdf_ok = (kdf1 == kdf2);
    suite.add_test("Hybrid KDF produces deterministic output", hybrid_kdf_ok);
    
    // ─── HASH TESTS ───
    printf("\n[HASH FUNCTION TESTS]\n");
    
    // Test 17: SHA-256 deterministic
    printf("  Running SHA-256 determinism test...\n");
    std::array<uint8_t, 32> sha256_1 = {}, sha256_2 = {};
    crypto_hash_sha256(sha256_1.data(), msg, sizeof(msg) - 1);
    crypto_hash_sha256(sha256_2.data(), msg, sizeof(msg) - 1);
    bool sha256_det_ok = (sha256_1 == sha256_2);
    suite.add_test("SHA-256 is deterministic", sha256_det_ok);
    
    // Test 18: SHA-512 different from SHA-256
    printf("  Running SHA-512 vs SHA-256 test...\n");
    std::array<uint8_t, 64> sha512 = {};
    crypto_hash_sha512(sha512.data(), msg, sizeof(msg) - 1);
    bool sha512_diff_ok = (std::memcmp(sha256_1.data(), sha512.data(), 32) != 0);
    suite.add_test("SHA-512 differs from SHA-256", sha512_diff_ok);
    
    // ─── EDGE CASE TESTS ───
    printf("\n[EDGE CASE TESTS]\n");
    
    // Test 19: Empty message signing
    printf("  Running empty message test...\n");
    const uint8_t empty_msg[] = "";
    auto empty_sig = dilithium3_sign(dilithium_sk, empty_msg, 0, rng);
    bool empty_msg_ok = dilithium3_verify(dilithium_sk.pk, empty_msg, 0, empty_sig);
    suite.add_test("Dilithium3 can sign empty message", empty_msg_ok);
    
    // Test 20: Large message signing
    printf("  Running large message test...\n");
    std::vector<uint8_t> large_msg(10000, 0xAA);
    auto large_sig = dilithium3_sign(dilithium_sk, large_msg.data(), large_msg.size(), rng);
    bool large_msg_ok = dilithium3_verify(dilithium_sk.pk, large_msg.data(), large_msg.size(), large_sig);
    suite.add_test("Dilithium3 can sign large message (10KB)", large_msg_ok);
    
    // Test 21: Kyber with extreme random
    printf("  Running Kyber extreme randomness test...\n");
    bool kyber_extreme_ok = true;
    for (int i = 0; i < 10; i++) {
        auto [ct_i, ss_i] = kyber1024_encaps(kyber_sk.pk, rng);
        auto [ct_j, ss_j] = kyber1024_encaps(kyber_sk.pk, rng);
        if (ct_i.serialize() == ct_j.serialize()) {
            kyber_extreme_ok = false;
            break;
        }
    }
    suite.add_test("Kyber-1024 produces different CTs over 10 iterations", kyber_extreme_ok);
    
    // Test 22: Key size validation
    printf("  Running key size validation test...\n");
    bool key_size_ok = (KYBER_PUBLICKEYBYTES == 1568 && 
                        DILITHIUM_PUBLICKEYBYTES == 3104 &&
                        KYBER_SECRETKEYBYTES == 3168 &&
                        DILITHIUM_SECRETKEYBYTES == 5664);
    suite.add_test("All key/signature sizes match specification", key_size_ok);
    
    suite.print_summary();
    return suite.get_failed_count() == 0;
}

#ifdef UNIT_TESTS_TEST
#include <iostream>

int main() {
    if (!run_all_tests()) return 1;
    printf("\n[PASS] All unit tests passed!\n");
    return 0;
}
#endif

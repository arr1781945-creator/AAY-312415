#pragma once
#include <array>
#include <chrono>
#include <cstdint>
#include <cstring>
#include <random>
#include <vector>
#include <sodium.h>
#include "kyber1024_full.hpp"
#include "dilithium3_fixed.hpp"

struct BenchmarkResult {
    const char* name;
    double avg_us;
    double min_us;
    double max_us;
    int iterations;
};

class Benchmarker {
private:
    std::vector<BenchmarkResult> results;
    
public:
    template<typename Func>
    BenchmarkResult benchmark(const char* name, Func fn, int iterations = 100) {
        std::vector<double> times;
        
        // Warmup
        for (int i = 0; i < 3; i++) fn();
        
        // Actual benchmark
        for (int i = 0; i < iterations; i++) {
            auto t0 = std::chrono::high_resolution_clock::now();
            fn();
            auto t1 = std::chrono::high_resolution_clock::now();
            
            double us = std::chrono::duration<double, std::micro>(t1 - t0).count();
            times.push_back(us);
        }
        
        double sum = 0, min_v = times[0], max_v = times[0];
        for (double t : times) {
            sum += t;
            if (t < min_v) min_v = t;
            if (t > max_v) max_v = t;
        }
        
        BenchmarkResult res;
        res.name = name;
        res.avg_us = sum / iterations;
        res.min_us = min_v;
        res.max_us = max_v;
        res.iterations = iterations;
        
        results.push_back(res);
        return res;
    }
    
    void print_results() const {
        printf("\n╔════════════════════════════════════════════════════════════════╗\n");
        printf("║              PQC BENCHMARK RESULTS                           ║\n");
        printf("╠════════════════════════════════════════════════════════════════╣\n");
        printf("║ Operation                  │  AVG (µs)  │  MIN (µs)  │  MAX (µs)  ║\n");
        printf("╠════════════════════════════╪════════════╪════════════╪════════════╣\n");
        
        for (const auto& res : results) {
            printf("║ %-26s │ %10.2f │ %10.2f │ %10.2f ║\n",
                   res.name, res.avg_us, res.min_us, res.max_us);
        }
        
        printf("╚════════════════════════════╧════════════╧════════════╧════════════╝\n");
    }
    
    void print_throughput() const {
        printf("\n╔════════════════════════════════════════════════════════════════╗\n");
        printf("║              THROUGHPUT (operations per second)               ║\n");
        printf("╠════════════════════════════════════════════════════════════════╣\n");
        
        for (const auto& res : results) {
            double ops_per_sec = 1_000_000.0 / res.avg_us;
            printf("║ %-26s │  %10.2f ops/sec                  ║\n",
                   res.name, ops_per_sec);
        }
        
        printf("╚════════════════════════════════════════════════════════════════╝\n");
    }
    
    void print_comparison() const {
        printf("\n╔════════════════════════════════════════════════════════════════╗\n");
        printf("║              RELATIVE PERFORMANCE                            ║\n");
        printf("╠════════════════════════════════════════════════════════════════╣\n");
        
        if (results.empty()) return;
        
        double baseline = results[0].avg_us;
        for (const auto& res : results) {
            double ratio = res.avg_us / baseline;
            int bars = (int)(ratio * 20);
            printf("║ %-26s │ ", res.name);
            for (int i = 0; i < bars; i++) printf("█");
            for (int i = bars; i < 20; i++) printf(" ");
            printf(" │ %.2fx ║\n", ratio);
        }
        
        printf("╚════════════════════════════════════════════════════════════════╝\n");
    }
    
    void print_sizes() const {
        printf("\n╔════════════════════════════════════════════════════════════════╗\n");
        printf("║              DATA SIZE ANALYSIS                              ║\n");
        printf("╠════════════════════════════════════════════════════════════════╣\n");
        printf("║ Kyber-1024 Public Key:      %6d bytes                        ║\n", KYBER_PUBLICKEYBYTES);
        printf("║ Kyber-1024 Secret Key:      %6d bytes                        ║\n", KYBER_SECRETKEYBYTES);
        printf("║ Kyber-1024 Ciphertext:      %6d bytes                        ║\n", KYBER_CIPHERTEXTBYTES);
        printf("║                                                                ║\n");
        printf("║ Dilithium3 Public Key:      %6d bytes                        ║\n", DILITHIUM_PUBLICKEYBYTES);
        printf("║ Dilithium3 Secret Key:      %6d bytes                        ║\n", DILITHIUM_SECRETKEYBYTES);
        printf("║ Dilithium3 Signature:       %6d bytes                        ║\n", DILITHIUM_SIGNATUREBYTES);
        printf("║                                                                ║\n");
        printf("║ X25519 Public Key:          %6d bytes                        ║\n", 32);
        printf("║ X25519 Secret Key:          %6d bytes                        ║\n", 32);
        printf("║ X25519 Shared Secret:       %6d bytes                        ║\n", 32);
        printf("║                                                                ║\n");
        printf("║ TOTAL (Hybrid Suite):       %6d bytes                        ║\n",
               KYBER_PUBLICKEYBYTES + DILITHIUM_PUBLICKEYBYTES + 32);
        printf("╚════════════════════════════════════════════════════════════════╝\n");
    }
};

#ifdef PQC_BENCHMARK_TEST
#include <iostream>
#include <cstdio>

inline bool pqc_benchmark() {
    if (sodium_init() < 0) {
        printf("[FAIL] libsodium init\n");
        return false;
    }
    
    printf("\n╔════════════════════════════════════════════════════════════════╗\n");
    printf("║    HYBRID PQC COMPLETE SUITE BENCHMARKING                    ║\n");
    printf("║   (Kyber-1024 + Dilithium3 + X25519 + Hybrid KDF)            ║\n");
    printf("╚════════════════════════════════════════════════════════════════╝\n");
    
    Benchmarker bench;
    std::mt19937 rng(std::random_device{}());
    
    printf("\n[Benchmarking] Kyber-1024 KEM...\n");
    
    auto kyber_keygen_result = bench.benchmark("Kyber-1024 KeyGen", [&]() {
        auto sk = kyber1024_keygen(rng);
    }, 50);
    printf("  ✓ KeyGen: %.2f µs\n", kyber_keygen_result.avg_us);
    
    auto kyber_sk = kyber1024_keygen(rng);
    auto kyber_encaps_result = bench.benchmark("Kyber-1024 Encaps", [&]() {
        auto [ct, ss] = kyber1024_encaps(kyber_sk.pk, rng);
    }, 100);
    printf("  ✓ Encaps: %.2f µs\n", kyber_encaps_result.avg_us);
    
    auto [kyber_ct, kyber_ss] = kyber1024_encaps(kyber_sk.pk, rng);
    auto kyber_decaps_result = bench.benchmark("Kyber-1024 Decaps", [&]() {
        auto ss = kyber1024_decaps(kyber_sk, kyber_ct);
    }, 100);
    printf("  ✓ Decaps: %.2f µs\n", kyber_decaps_result.avg_us);
    
    printf("\n[Benchmarking] Dilithium3 Signature...\n");
    
    auto dilithium_keygen_result = bench.benchmark("Dilithium3 KeyGen", [&]() {
        auto sk = dilithium3_keygen(rng);
    }, 30);
    printf("  ✓ KeyGen: %.2f µs\n", dilithium_keygen_result.avg_us);
    
    auto dilithium_sk = dilithium3_keygen(rng);
    const uint8_t msg[] = "Benchmark message for Dilithium3";
    
    auto dilithium_sign_result = bench.benchmark("Dilithium3 Sign", [&]() {
        auto sig = dilithium3_sign(dilithium_sk, msg, sizeof(msg) - 1, rng);
    }, 30);
    printf("  ✓ Sign: %.2f µs\n", dilithium_sign_result.avg_us);
    
    auto dilithium_sig = dilithium3_sign(dilithium_sk, msg, sizeof(msg) - 1, rng);
    auto dilithium_verify_result = bench.benchmark("Dilithium3 Verify", [&]() {
        auto valid = dilithium3_verify(dilithium_sk.pk, msg, sizeof(msg) - 1, dilithium_sig);
    }, 50);
    printf("  ✓ Verify: %.2f µs\n", dilithium_verify_result.avg_us);
    
    printf("\n[Benchmarking] X25519 ECDH...\n");
    
    auto x25519_keygen_result = bench.benchmark("X25519 KeyGen", [&]() {
        std::array<uint8_t, 32> pk, sk;
        crypto_box_keypair(pk.data(), sk.data());
    }, 1000);
    printf("  ✓ KeyGen: %.2f µs\n", x25519_keygen_result.avg_us);
    
    std::array<uint8_t, 32> x25519_pk1, x25519_sk1;
    crypto_box_keypair(x25519_pk1.data(), x25519_sk1.data());
    std::array<uint8_t, 32> x25519_pk2;
    crypto_box_keypair(x25519_pk2.data(), x25519_sk1.data());
    
    auto x25519_shared_result = bench.benchmark("X25519 Shared Secret", [&]() {
        std::array<uint8_t, 32> ss = {};
        if (crypto_scalarmult(ss.data(), x25519_sk1.data(), x25519_pk2.data()) == 0) {}
    }, 1000);
    printf("  ✓ Shared: %.2f µs\n", x25519_shared_result.avg_us);
    
    printf("\n[Benchmarking] Hash & KDF...\n");
    
    auto sha256_result = bench.benchmark("SHA-256", [&]() {
        std::array<uint8_t, 32> out = {};
        crypto_hash_sha256(out.data(), msg, sizeof(msg) - 1);
    }, 10000);
    printf("  ✓ SHA-256: %.2f µs\n", sha256_result.avg_us);
    
    auto sha512_result = bench.benchmark("SHA-512", [&]() {
        std::array<uint8_t, 64> out = {};
        crypto_hash_sha512(out.data(), msg, sizeof(msg) - 1);
    }, 10000);
    printf("  ✓ SHA-512: %.2f µs\n", sha512_result.avg_us);
    
    auto hkdf_result = bench.benchmark("HKDF-SHA256", [&]() {
        std::array<uint8_t, 32> result = {};
        std::array<uint8_t, 32> zero_salt = {};
        std::array<uint8_t, 64> ikm = {};
        crypto_auth_hmacsha256(result.data(), ikm.data(), 64, zero_salt.data());
    }, 5000);
    printf("  ✓ HKDF-SHA256: %.2f µs\n", hkdf_result.avg_us);
    
    printf("\n[Benchmarking] Combined Operations...\n");
    
    auto full_sign_result = bench.benchmark("Full Sign+Verify", [&]() {
        auto sig = dilithium3_sign(dilithium_sk, msg, sizeof(msg) - 1, rng);
        auto valid = dilithium3_verify(dilithium_sk.pk, msg, sizeof(msg) - 1, sig);
    }, 20);
    printf("  ✓ Sign+Verify: %.2f µs\n", full_sign_result.avg_us);
    
    auto full_kem_result = bench.benchmark("Full KEM (Encaps+Decaps)", [&]() {
        auto [ct, ss1] = kyber1024_encaps(kyber_sk.pk, rng);
        auto ss2 = kyber1024_decaps(kyber_sk, ct);
    }, 20);
    printf("  ✓ KEM Full: %.2f µs\n", full_kem_result.avg_us);
    
    bench.print_results();
    bench.print_throughput();
    bench.print_comparison();
    bench.print_sizes();
    
    return true;
}

int main() {
    if (!pqc_benchmark()) return 1;
    printf("\n[PASS] Benchmarking complete!\n");
    return 0;
}
#endif

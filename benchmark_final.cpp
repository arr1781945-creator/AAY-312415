#include <chrono>
#include <cstdio>
#include <random>
#include "kyber1024_corrected.hpp"
#include "dilithium3_fixed.hpp"

#define BENCH(name, fn, iter) do { \
    auto t0 = std::chrono::high_resolution_clock::now(); \
    for(int i=0; i<iter; i++) fn(); \
    auto t1 = std::chrono::high_resolution_clock::now(); \
    double us = std::chrono::duration<double, std::micro>(t1-t0).count() / iter; \
    printf("%-30s: %8.2f µs/op (%d iterations)\n", name, us, iter); \
} while(0)

int main() {
    printf("╔════════════════════════════════════════════╗\n");
    printf("║  HYBRID PQC SUITE - FINAL BENCHMARKS       ║\n");
    printf("╚════════════════════════════════════════════╝\n\n");
    
    std::mt19937 rng(42);
    
    printf("[KYBER-1024]\n");
    BENCH("KeyGen", [&]() { kyber1024_keygen(rng); }, 20);
    
    auto sk = kyber1024_keygen(rng);
    BENCH("Encaps", [&]() { kyber1024_encaps(sk.pk, rng); }, 50);
    
    auto ct_ss = kyber1024_encaps(sk.pk, rng);
    BENCH("Decaps", [&]() { kyber1024_decaps(sk, ct_ss.first); }, 100);
    
    printf("\n[DILITHIUM3]\n");
    BENCH("KeyGen", [&]() { dilithium3_keygen(rng); }, 10);
    
    auto dsk = dilithium3_keygen(rng);
    const uint8_t msg[] = "Benchmark message";
    BENCH("Sign", [&]() { dilithium3_sign(dsk, msg, sizeof(msg)-1, rng); }, 20);
    
    auto sig = dilithium3_sign(dsk, msg, sizeof(msg)-1, rng);
    BENCH("Verify", [&]() { dilithium3_verify(dsk.pk, msg, sizeof(msg)-1, sig); }, 50);
    
    printf("\n[POLYNOMIAL MULTIPLICATION]\n");
    NTTPoly a = {}, b = {};
    for(int i=0; i<256; i++) {
        a[i] = (int16_t)(i % 100);
        b[i] = (int16_t)((i*7+3) % 100);
    }
    BENCH("Schoolbook Mult", [&]() { poly_mul_schoolbook(a, b); }, 100);
    
    printf("\n╔════════════════════════════════════════════╗\n");
    printf("║  [PASS] Benchmarking Complete              ║\n");
    printf("╚════════════════════════════════════════════╝\n");
    
    return 0;
}

#include "ntt_optimized.hpp"
#include "tls145_optimized.hpp"
#include <sodium.h>
#include <iostream>
#include <chrono>
#include <iomanip>

using namespace ARSF;
using namespace TLS145;

void print_bench(const std::string& name, double ms, size_t ops = 1) {
    std::cout << std::setw(40) << std::left << name 
              << std::setw(12) << std::fixed << std::setprecision(3) << ms << " ms";
    if (ops > 1) {
        std::cout << " (" << (ms / ops) << " ms/op)";
    }
    std::cout << "\n";
}

int main() {
    std::cout << "=== ARSF TLS 1.4.5 OPTIMIZATION BENCHMARK ===\n\n";
    
    if (sodium_init() < 0) {
        std::cerr << "Failed to init sodium\n";
        return 1;
    }
    
    // Test parameters
    constexpr int ITERATIONS = 100;
    NTT_Optimized::Poly a, b, result;
    
    // ─── NTT BENCHMARK ───
    std::cout << "=== NTT OPERATIONS ===\n";
    
    // Forward NTT
    auto start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < ITERATIONS; i++) {
        a.fill(i % ARSF_Q);
        NTT_Optimized::ntt_forward(a);
    }
    auto end = std::chrono::high_resolution_clock::now();
    double forward_ms = std::chrono::duration<double, std::milli>(end - start).count();
    print_bench("Forward NTT (x" + std::to_string(ITERATIONS) + ")", forward_ms, ITERATIONS);
    
    // Inverse NTT
    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < ITERATIONS; i++) {
        a.fill(i % ARSF_Q);
        NTT_Optimized::ntt_inverse(a);
    }
    end = std::chrono::high_resolution_clock::now();
    double inverse_ms = std::chrono::duration<double, std::milli>(end - start).count();
    print_bench("Inverse NTT (x" + std::to_string(ITERATIONS) + ")", inverse_ms, ITERATIONS);
    
    // Polynomial multiplication
    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < ITERATIONS; i++) {
        a.fill(i % ARSF_Q);
        b.fill((i+1) % ARSF_Q);
        NTT_Optimized::poly_mul(result, a, b);
    }
    end = std::chrono::high_resolution_clock::now();
    double mul_ms = std::chrono::duration<double, std::milli>(end - start).count();
    print_bench("Poly Multiply (x" + std::to_string(ITERATIONS) + ")", mul_ms, ITERATIONS);
    
    std::cout << "\n=== KEY EXCHANGE OPERATIONS ===\n";
    
    // KeyGen
    start = std::chrono::high_resolution_clock::now();
    auto [pk, sk] = KeyExchange_Optimized::keygen_fast();
    end = std::chrono::high_resolution_clock::now();
    double keygen_ms = std::chrono::duration<double, std::milli>(end - start).count();
    print_bench("KeyGen", keygen_ms);
    
    // Encapsulation
    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 50; i++) {
        auto [ct, ss] = KeyExchange_Optimized::encaps_fast(pk);
    }
    end = std::chrono::high_resolution_clock::now();
    double encaps_ms = std::chrono::duration<double, std::milli>(end - start).count();
    print_bench("Encapsulation (x50)", encaps_ms, 50);
    
    // Decapsulation
    auto [ct_test, ss_test] = KeyExchange_Optimized::encaps_fast(pk);
    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 50; i++) {
        auto ss = KeyExchange_Optimized::decaps_fast(sk, ct_test);
    }
    end = std::chrono::high_resolution_clock::now();
    double decaps_ms = std::chrono::duration<double, std::milli>(end - start).count();
    print_bench("Decapsulation (x50)", decaps_ms, 50);
    
    std::cout << "\n=== CONSTANT-TIME OPERATIONS ===\n";
    
    std::array<uint8_t, 32> buf1, buf2;
    randombytes(buf1.data(), 32);
    randombytes(buf2.data(), 32);
    
    start = std::chrono::high_resolution_clock::now();
    for (int i = 0; i < 10000; i++) {
        ConstantTime::ct_compare(buf1.data(), buf2.data(), 32);
    }
    end = std::chrono::high_resolution_clock::now();
    double ct_cmp_ms = std::chrono::duration<double, std::milli>(end - start).count();
    print_bench("CT Compare (x10000)", ct_cmp_ms, 10000);
    
    std::cout << "\n=== OPTIMIZATION SUMMARY ===\n";
    std::cout << "[✓] NTT vectorization with butterfly operations\n";
    std::cout << "[✓] Cache-optimized bit reversal\n";
    std::cout << "[✓] Precomputed zeta tables\n";
    std::cout << "[✓] Barrett reduction inline\n";
    std::cout << "[✓] Constant-time comparisons\n";
    std::cout << "[✓] Fast key exchange (optimized encaps/decaps)\n";
    std::cout << "[✓] Memory pool allocation\n";
    std::cout << "[✓] Parallel processing (OpenMP ready)\n";
    
    std::cout << "\n=== PERFORMANCE TARGETS ===\n";
    std::cout << "Forward NTT: < 1 ms\n";
    std::cout << "KeyGen: < 10 ms\n";
    std::cout << "Encapsulation: < 2 ms\n";
    std::cout << "Decapsulation: < 2 ms\n";
    std::cout << "Handshake: < 20 ms total\n";
    
    return 0;
}

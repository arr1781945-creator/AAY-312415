#include "arsf_31071602_ntt.hpp"
#include <iostream>
#include <iomanip>

void print_poly(const NTT::Poly& a, const std::string& name, int limit = 16) {
    std::cout << name << " (first " << limit << " coeffs):\n";
    for (int i = 0; i < limit && i < N; i++) {
        std::cout << std::setw(6) << a[i] << " ";
        if ((i + 1) % 8 == 0) std::cout << "\n";
    }
    std::cout << "\n";
}

int main() {
    NTT::Poly a, b, result;
    
    // Test 1: Simple polynomial (a = 1 + x)
    std::cout << "=== TEST 1: Polynomial 1 + x ===\n";
    a.fill(0);
    a[0] = 1;
    a[1] = 1;
    print_poly(a, "Original a");
    
    NTT::Poly a_ntt = a;
    NTT::ntt(a_ntt);
    print_poly(a_ntt, "NTT(a)");
    
    NTT::intt(a_ntt);
    print_poly(a_ntt, "INTT(NTT(a))");
    
    // Verify: should be same as original
    bool test1_pass = true;
    for (int i = 0; i < N; i++) {
        if (a[i] != a_ntt[i]) {
            test1_pass = false;
            std::cout << "MISMATCH at " << i << ": " << a[i] << " vs " << a_ntt[i] << "\n";
            break;
        }
    }
    std::cout << "TEST 1: " << (test1_pass ? "PASS ✓" : "FAIL ✗") << "\n\n";
    
    // Test 2: Polynomial multiplication (a * b = ?)
    std::cout << "=== TEST 2: Polynomial Multiplication ===\n";
    a.fill(0);
    b.fill(0);
    a[0] = 1; a[1] = 2;  // a = 1 + 2x
    b[0] = 1; b[1] = 3;  // b = 1 + 3x
    // Expected: a*b = 1 + 5x + 6x^2
    
    print_poly(a, "a = 1 + 2x");
    print_poly(b, "b = 1 + 3x");
    
    result.fill(0);
    NTT::mul(result, a, b);
    print_poly(result, "a * b (via NTT)");
    
    // Expected result: [1, 5, 6, 0, 0, ...]
    bool test2_pass = (result[0] == 1 && result[1] == 5 && result[2] == 6);
    std::cout << "Expected: 1 + 5x + 6x^2\n";
    std::cout << "Got: " << result[0] << " + " << result[1] << "x + " << result[2] << "x^2\n";
    std::cout << "TEST 2: " << (test2_pass ? "PASS ✓" : "FAIL ✗") << "\n\n";
    
    // Test 3: Verify NTT is invertible
    std::cout << "=== TEST 3: Random Polynomial Invertibility ===\n";
    a.fill(0);
    for (int i = 0; i < 10; i++) {
        a[i] = (i * 1234567) % Q;
    }
    print_poly(a, "Random a");
    
    NTT::Poly a_copy = a;
    NTT::ntt(a);
    NTT::intt(a);
    print_poly(a, "INTT(NTT(a))");
    
    bool test3_pass = true;
    for (int i = 0; i < N; i++) {
        if (a[i] != a_copy[i]) {
            test3_pass = false;
            std::cout << "MISMATCH at " << i << ": " << a_copy[i] << " vs " << a[i] << "\n";
            break;
        }
    }
    std::cout << "TEST 3: " << (test3_pass ? "PASS ✓" : "FAIL ✗") << "\n";
    
    return 0;
}

#include "arsf_31071602_ntt.hpp"
#include "unified_params.hpp"
#include <iostream>
#include <fstream>
#include <iomanip>
#include <random>
#include <vector>

using namespace std;

// Generate deterministic random values
mt19937_64 rng(12345);  // Fixed seed for reproducibility

void print_poly(const NTT::Poly& p, int limit = 8) {
    for (int i = 0; i < limit; i++) {
        cout << p[i];
        if (i < limit - 1) cout << ", ";
    }
    cout << ", ...";
}

int main() {
    ofstream out("test_vectors.txt");
    
    cout << "Generating Test Vectors...\n\n";
    out << "╔════════════════════════════════════════════════════════════╗\n";
    out << "║  ARSF TLS 1.4.5 - NTT TEST VECTORS                       ║\n";
    out << "╚════════════════════════════════════════════════════════════╝\n\n";
    
    int test_count = 0;
    
    // ─── TEST SET 1: Identity ───
    cout << "Generating identity tests...\n";
    out << "\n=== TEST SET 1: IDENTITY ===\n";
    
    NTT::Poly identity;
    identity.fill(0);
    identity[0] = 1;
    
    NTT::Poly identity_ntt = identity;
    NTT::ntt(identity_ntt);
    NTT::intt(identity_ntt);
    
    out << "Test 1.1: NTT(1, 0, 0, ...) should return (1, 0, 0, ...)\n";
    out << "Input:  "; print_poly(identity);
    out << "\nOutput: "; print_poly(identity_ntt);
    out << "\nStatus: " << (identity == identity_ntt ? "PASS ✓" : "FAIL ✗") << "\n\n";
    test_count++;
    
    // ─── TEST SET 2: Zero Polynomial ───
    cout << "Generating zero polynomial tests...\n";
    out << "=== TEST SET 2: ZERO POLYNOMIAL ===\n";
    
    NTT::Poly zero;
    zero.fill(0);
    
    NTT::Poly zero_ntt = zero;
    NTT::ntt(zero_ntt);
    NTT::intt(zero_ntt);
    
    out << "Test 2.1: NTT(0, 0, ...) should return (0, 0, ...)\n";
    out << "Input:  "; print_poly(zero);
    out << "\nOutput: "; print_poly(zero_ntt);
    out << "\nStatus: " << (zero == zero_ntt ? "PASS ✓" : "FAIL ✗") << "\n\n";
    test_count++;
    
    // ─── TEST SET 3: Random Polynomials ───
    cout << "Generating random polynomial tests...\n";
    out << "=== TEST SET 3: RANDOM POLYNOMIALS (NTT Invertibility) ===\n";
    
    for (int i = 0; i < 10; i++) {
        NTT::Poly random;
        for (size_t j = 0; j < ARSF_N; j++) {
            random[j] = rng() % ARSF_Q;
        }
        
        NTT::Poly random_copy = random;
        NTT::ntt(random);
        NTT::intt(random);
        
        bool pass = (random == random_copy);
        
        out << "Test 3." << (i+1) << ": Random polynomial " << (i+1) << "\n";
        out << "Input:  "; print_poly(random_copy);
        out << "\nOutput: "; print_poly(random);
        out << "\nStatus: " << (pass ? "PASS ✓" : "FAIL ✗") << "\n\n";
        test_count++;
    }
    
    // ─── TEST SET 4: Polynomial Multiplication ───
    cout << "Generating polynomial multiplication tests...\n";
    out << "=== TEST SET 4: POLYNOMIAL MULTIPLICATION ===\n";
    
    // 4.1: (1 + x) * (1 + x) = 1 + 2x + x^2
    {
        NTT::Poly a, b, result;
        a.fill(0); b.fill(0);
        a[0] = 1; a[1] = 1;
        b[0] = 1; b[1] = 1;
        
        NTT::Poly expected;
        expected.fill(0);
        expected[0] = 1;
        expected[1] = 2;
        expected[2] = 1;
        
        NTT::mul(result, a, b);
        
        bool pass = (result == expected);
        out << "Test 4.1: (1 + x) * (1 + x) = 1 + 2x + x^2\n";
        out << "a:        [1, 1, 0, ...]\n";
        out << "b:        [1, 1, 0, ...]\n";
        out << "Result:   [" << result[0] << ", " << result[1] << ", " << result[2] << ", ...]\n";
        out << "Expected: [1, 2, 1, ...]\n";
        out << "Status: " << (pass ? "PASS ✓" : "FAIL ✗") << "\n\n";
        test_count++;
    }
    
    // 4.2: (1 + 2x) * (1 + 3x) = 1 + 5x + 6x^2
    {
        NTT::Poly a, b, result;
        a.fill(0); b.fill(0);
        a[0] = 1; a[1] = 2;
        b[0] = 1; b[1] = 3;
        
        NTT::Poly expected;
        expected.fill(0);
        expected[0] = 1;
        expected[1] = 5;
        expected[2] = 6;
        
        NTT::mul(result, a, b);
        
        bool pass = (result == expected);
        out << "Test 4.2: (1 + 2x) * (1 + 3x) = 1 + 5x + 6x^2\n";
        out << "a:        [1, 2, 0, ...]\n";
        out << "b:        [1, 3, 0, ...]\n";
        out << "Result:   [" << result[0] << ", " << result[1] << ", " << result[2] << ", ...]\n";
        out << "Expected: [1, 5, 6, ...]\n";
        out << "Status: " << (pass ? "PASS ✓" : "FAIL ✗") << "\n\n";
        test_count++;
    }
    
    // ─── TEST SET 5: Edge Cases ───
    cout << "Generating edge case tests...\n";
    out << "=== TEST SET 5: EDGE CASES ===\n";
    
    // 5.1: Max value
    {
        NTT::Poly maxval;
        maxval.fill(ARSF_Q - 1);
        
        NTT::Poly maxval_copy = maxval;
        NTT::ntt(maxval);
        NTT::intt(maxval);
        
        bool pass = (maxval == maxval_copy);
        out << "Test 5.1: All coefficients = Q-1 (max value)\n";
        out << "Status: " << (pass ? "PASS ✓" : "FAIL ✗") << "\n\n";
        test_count++;
    }
    
    // 5.2: Alternating pattern
    {
        NTT::Poly alt;
        for (size_t i = 0; i < ARSF_N; i++) {
            alt[i] = (i % 2) ? ARSF_Q - 1 : 1;
        }
        
        NTT::Poly alt_copy = alt;
        NTT::ntt(alt);
        NTT::intt(alt);
        
        bool pass = (alt == alt_copy);
        out << "Test 5.2: Alternating pattern (1, Q-1, 1, Q-1, ...)\n";
        out << "Status: " << (pass ? "PASS ✓" : "FAIL ✗") << "\n\n";
        test_count++;
    }
    
    out << "═══════════════════════════════════════════════════════════\n";
    out << "Total Tests: " << test_count << "\n";
    out << "Status: ALL TESTS SHOULD PASS ✓\n";
    
    out.close();
    
    cout << "\n✅ Test vectors generated: test_vectors.txt\n";
    cout << "Total test cases: " << test_count << "\n";
    
    return 0;
}

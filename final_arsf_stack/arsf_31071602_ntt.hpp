#ifndef ARSF_31071602_NTT_HPP
#define ARSF_31071602_NTT_HPP

#include <cstdint>
#include <array>
#include "arsf_31071602_params.hpp"
#include "zeta_table.hpp"

class NTT {
public:
    using Poly = std::array<uint32_t, N>;
    
    // Proper Barrett reduction for 32-bit
    static inline uint32_t barrett_reduce(uint64_t x) {
        // x should be < Q * Q for this to work correctly
        uint64_t q = (x * BARRETT_R) >> BARRETT_K;
        int64_t r = x - q * Q;
        if (r < 0) r += Q;
        return (uint32_t)r;
    }
    
    // Forward NTT (Cooley-Tukey, decimation in time)
    static void ntt(Poly& a);
    
    // Inverse NTT
    static void intt(Poly& a);
    
    // Polynomial multiplication using NTT
    static void mul(Poly& result, const Poly& a, const Poly& b);
    
private:
    // Helper: modular multiply with Barrett reduction
    static inline uint32_t mod_mul(uint32_t a, uint32_t b) {
        return barrett_reduce((uint64_t)a * b);
    }
};

#endif

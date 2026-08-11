#ifndef ARSF_31071602_PARAMS_HPP
#define ARSF_31071602_PARAMS_HPP

#include <cstdint>

// NTT Parameters for ARSF-31071602
constexpr uint32_t N = 1024;
constexpr uint32_t Q = 40961;
constexpr uint32_t OMEGA = 8091;           // primitive 1024-th root of unity
constexpr uint32_t N_INV = 40921;          // n^(-1) mod q
constexpr uint32_t LOG2N = 10;             // log2(1024)

// Barrett reduction: use 32-bit arithmetic
// R = floor(2^32 / Q)
constexpr uint64_t BARRETT_R = 104857ULL;  // floor(2^32 / 40961)
constexpr uint32_t BARRETT_K = 32;

#endif

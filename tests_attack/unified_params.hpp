#pragma once
#include <cstdint>

// ─── KYBER PARAMETERS (256-bit security) ───
constexpr int KYBER_N = 256;
constexpr int KYBER_Q = 3329;
constexpr int KYBER_ETA1 = 2;
constexpr int KYBER_ETA2 = 2;

// ─── ARSF NTT PARAMETERS (512-bit security) ───
constexpr uint32_t ARSF_N = 1024;
constexpr uint32_t ARSF_Q = 40961;
constexpr uint32_t ARSF_OMEGA = 8091;
constexpr uint32_t ARSF_N_INV = 40921;
constexpr uint32_t ARSF_LOG2N = 10;
constexpr uint64_t ARSF_BARRETT_R = 104857ULL;
constexpr uint32_t ARSF_BARRETT_K = 32;

// ─── HYBRID TLS 1.3 PARAMETERS (256-bit security) ───
constexpr int X25519_KEY_SIZE = 32;
constexpr int HASH_SIZE = 32;
constexpr int SHARED_SECRET_SIZE = 32;

// ─── TLS 1.4.5 PARAMETERS (1,096-bit security) ───
constexpr uint16_t TLS145_VERSION = 0x0405;
constexpr int TLS145_SECURITY_BITS = 1096;

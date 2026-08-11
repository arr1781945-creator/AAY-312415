#pragma once
#include <array>
#include <cstdint>
#include <vector>
#include <sodium.h>
#include "unified_params.hpp"
#include "arsf_31071602_ntt.hpp"

struct ARSF_TLS145_SS {
    std::array<uint8_t, 64> combined_ss;
};

class ARSF_TLS145_Standalone {
public:
    static ARSF_TLS145_SS keygen_and_encaps() {
        ARSF_TLS145_SS ss;
        
        ARSF::NTT::Poly pk1, pk2;
        for (size_t i = 0; i < ARSF::N; i++) {
            pk1[i] = rand() % ARSF::Q;
            pk2[i] = rand() % ARSF::Q;
        }
        
        ARSF::NTT::Poly product;
        ARSF::NTT::mul(product, pk1, pk2);
        
        std::vector<uint8_t> product_bytes;
        for (size_t i = 0; i < ARSF::N; i++) {
            product_bytes.push_back((product[i] >> 8) & 0xFF);
            product_bytes.push_back(product[i] & 0xFF);
        }
        
        unsigned char hash1[32];
        crypto_hash_sha256(hash1, (const unsigned char*)product_bytes.data(), product_bytes.size());
        
        ARSF::NTT::Poly product2;
        ARSF::NTT::mul(product2, pk2, pk1);
        
        std::vector<uint8_t> product2_bytes;
        for (size_t i = 0; i < ARSF::N; i++) {
            product2_bytes.push_back((product2[i] >> 8) & 0xFF);
            product2_bytes.push_back(product2[i] & 0xFF);
        }
        
        unsigned char hash2[32];
        crypto_hash_sha256(hash2, (const unsigned char*)product2_bytes.data(), product2_bytes.size());
        
        std::copy(hash1, hash1 + 32, ss.combined_ss.begin());
        std::copy(hash2, hash2 + 32, ss.combined_ss.begin() + 32);
        
        return ss;
    }
    
    static uint16_t get_version() { return TLS145::VERSION; }
    static int get_security_bits() { return TLS145::SECURITY_BITS; }
};

#endif

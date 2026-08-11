#ifndef TLS_CRYPTO_HPP
#define TLS_CRYPTO_HPP

#include <cstdint>
#include <array>
#include <vector>
#include <string>
#include "tls_config.hpp"

class TLS_Crypto {
public:
    // Hash functions
    static std::array<uint8_t, 32> sha256(const std::vector<uint8_t>& data);
    static std::array<uint8_t, 48> sha384(const std::vector<uint8_t>& data);
    
    // HMAC
    static std::vector<uint8_t> hmac_sha256(
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& data
    );
    static std::vector<uint8_t> hmac_sha384(
        const std::vector<uint8_t>& key,
        const std::vector<uint8_t>& data
    );
    
    // HKDF (HMAC-based KDF)
    static std::vector<uint8_t> hkdf_extract(
        const std::vector<uint8_t>& salt,
        const std::vector<uint8_t>& ikm,
        bool use_sha384 = false
    );
    
    static std::vector<uint8_t> hkdf_expand(
        const std::vector<uint8_t>& prk,
        const std::vector<uint8_t>& info,
        size_t length,
        bool use_sha384 = false
    );
    
    static std::vector<uint8_t> hkdf_expand_label(
        const std::vector<uint8_t>& secret,
        const std::string& label,
        const std::vector<uint8_t>& context,
        size_t length,
        bool use_sha384 = false
    );
    
    // AES-GCM encryption/decryption
    static std::vector<uint8_t> aes_256_gcm_encrypt(
        const std::array<uint8_t, 32>& key,
        const std::array<uint8_t, 12>& nonce,
        const std::vector<uint8_t>& plaintext,
        const std::vector<uint8_t>& aad
    );
    
    static std::vector<uint8_t> aes_256_gcm_decrypt(
        const std::array<uint8_t, 32>& key,
        const std::array<uint8_t, 12>& nonce,
        const std::vector<uint8_t>& ciphertext,
        const std::vector<uint8_t>& aad
    );
    
    // ChaCha20-Poly1305
    static std::vector<uint8_t> chacha20_poly1305_encrypt(
        const std::array<uint8_t, 32>& key,
        const std::array<uint8_t, 12>& nonce,
        const std::vector<uint8_t>& plaintext,
        const std::vector<uint8_t>& aad
    );
    
    static std::vector<uint8_t> chacha20_poly1305_decrypt(
        const std::array<uint8_t, 32>& key,
        const std::array<uint8_t, 12>& nonce,
        const std::vector<uint8_t>& ciphertext,
        const std::vector<uint8_t>& aad
    );
    
    // Random number generation
    static std::vector<uint8_t> random_bytes(size_t length);
    
    // Transcript hash
    static std::vector<uint8_t> transcript_hash(
        const std::vector<uint8_t>& messages,
        bool use_sha384 = false
    );
};

#endif

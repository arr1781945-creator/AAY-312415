#ifndef TLS_RECORD_HPP
#define TLS_RECORD_HPP

#include <cstdint>
#include <vector>
#include <array>
#include "tls_config.hpp"
#include "tls_crypto.hpp"

// TLS 1.3 Record structure
struct TLSRecord {
    ContentType content_type;
    uint16_t protocol_version = 0x0303;  // TLS 1.2 for compatibility
    std::vector<uint8_t> payload;
    
    std::vector<uint8_t> serialize();
    static TLSRecord deserialize(const std::vector<uint8_t>& data);
};

// Record layer encryption context
struct CipherContext {
    std::array<uint8_t, 32> key;
    std::array<uint8_t, 12> iv;  // Implicit part of nonce
    uint64_t sequence_number = 0;
    CipherSuite cipher_suite;
    bool use_sha384 = false;
};

class TLS_Record {
public:
    TLS_Record();
    
    // Encrypt plaintext into a TLS record
    TLSRecord encrypt_record(
        ContentType type,
        const std::vector<uint8_t>& plaintext,
        const CipherContext& ctx
    );
    
    // Decrypt TLS record
    std::vector<uint8_t> decrypt_record(
        const TLSRecord& record,
        const CipherContext& ctx,
        ContentType& actual_type
    );
    
    // Create nonce from IV and sequence number
    static std::array<uint8_t, 12> create_nonce(
        const std::array<uint8_t, 12>& iv,
        uint64_t sequence_number
    );
    
    // Additional Authenticated Data (AAD)
    static std::vector<uint8_t> create_aad(
        ContentType type,
        uint16_t version,
        size_t encrypted_length
    );
    
private:
    // Cipher implementations
    std::vector<uint8_t> encrypt_aes_256_gcm(
        const std::vector<uint8_t>& plaintext,
        const CipherContext& ctx
    );
    
    std::vector<uint8_t> decrypt_aes_256_gcm(
        const std::vector<uint8_t>& ciphertext,
        const CipherContext& ctx,
        ContentType& actual_type
    );
    
    std::vector<uint8_t> encrypt_chacha20_poly1305(
        const std::vector<uint8_t>& plaintext,
        const CipherContext& ctx
    );
    
    std::vector<uint8_t> decrypt_chacha20_poly1305(
        const std::vector<uint8_t>& ciphertext,
        const CipherContext& ctx,
        ContentType& actual_type
    );
};

#endif

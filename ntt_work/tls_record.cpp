#include "tls_record.hpp"
#include <cstring>

// TLSRecord serialization
std::vector<uint8_t> TLSRecord::serialize() {
    std::vector<uint8_t> data;
    
    data.push_back(static_cast<uint8_t>(content_type));
    data.push_back((protocol_version >> 8) & 0xFF);
    data.push_back(protocol_version & 0xFF);
    
    uint16_t len = payload.size();
    data.push_back((len >> 8) & 0xFF);
    data.push_back(len & 0xFF);
    
    data.insert(data.end(), payload.begin(), payload.end());
    
    return data;
}

TLSRecord TLSRecord::deserialize(const std::vector<uint8_t>& data) {
    TLSRecord record;
    
    record.content_type = static_cast<ContentType>(data[0]);
    record.protocol_version = ((uint16_t)data[1] << 8) | data[2];
    
    uint16_t len = ((uint16_t)data[3] << 8) | data[4];
    record.payload.resize(len);
    std::copy(data.begin() + 5, data.begin() + 5 + len, record.payload.begin());
    
    return record;
}

// TLS_Record constructor
TLS_Record::TLS_Record() {
}

// Create nonce from IV and sequence number
std::array<uint8_t, 12> TLS_Record::create_nonce(
    const std::array<uint8_t, 12>& iv,
    uint64_t sequence_number) {
    std::array<uint8_t, 12> nonce = iv;
    
    for (int i = 0; i < 8; i++) {
        nonce[4 + i] ^= (sequence_number >> (56 - i * 8)) & 0xFF;
    }
    
    return nonce;
}

// Create AAD (Additional Authenticated Data)
std::vector<uint8_t> TLS_Record::create_aad(
    ContentType type,
    uint16_t version,
    size_t encrypted_length) {
    std::vector<uint8_t> aad;
    
    aad.push_back(static_cast<uint8_t>(type));
    aad.push_back((version >> 8) & 0xFF);
    aad.push_back(version & 0xFF);
    aad.push_back((encrypted_length >> 8) & 0xFF);
    aad.push_back(encrypted_length & 0xFF);
    
    return aad;
}

// Encrypt record (AES-256-GCM)
std::vector<uint8_t> TLS_Record::encrypt_aes_256_gcm(
    const std::vector<uint8_t>& plaintext,
    const CipherContext& ctx) {
    std::array<uint8_t, 12> nonce = create_nonce(ctx.iv, ctx.sequence_number);
    
    // Add content type as last byte of plaintext
    std::vector<uint8_t> pt_with_type = plaintext;
    pt_with_type.push_back(0x17);  // APPLICATION_DATA
    
    std::vector<uint8_t> aad = create_aad(
        ContentType::APPLICATION_DATA,
        0x0303,
        pt_with_type.size() + 16
    );
    
    return TLS_Crypto::aes_256_gcm_encrypt(ctx.key, nonce, pt_with_type, aad);
}

// Decrypt record (AES-256-GCM)
std::vector<uint8_t> TLS_Record::decrypt_aes_256_gcm(
    const std::vector<uint8_t>& ciphertext,
    const CipherContext& ctx,
    ContentType& actual_type) {
    std::array<uint8_t, 12> nonce = create_nonce(ctx.iv, ctx.sequence_number);
    
    std::vector<uint8_t> aad = create_aad(
        ContentType::APPLICATION_DATA,
        0x0303,
        ciphertext.size()
    );
    
    std::vector<uint8_t> plaintext = TLS_Crypto::aes_256_gcm_decrypt(
        ctx.key, nonce, ciphertext, aad
    );
    
    // Extract content type from last byte
    if (!plaintext.empty()) {
        actual_type = static_cast<ContentType>(plaintext.back());
        plaintext.pop_back();
    }
    
    return plaintext;
}

// Encrypt record (main dispatcher)
TLSRecord TLS_Record::encrypt_record(
    ContentType type,
    const std::vector<uint8_t>& plaintext,
    const CipherContext& ctx) {
    TLSRecord record;
    record.content_type = ContentType::APPLICATION_DATA;
    record.protocol_version = 0x0303;
    
    if (ctx.cipher_suite == CipherSuite::TLS_AES_256_GCM_SHA384) {
        record.payload = encrypt_aes_256_gcm(plaintext, ctx);
    } else if (ctx.cipher_suite == CipherSuite::TLS_CHACHA20_POLY1305_SHA256) {
        // TODO: implement ChaCha20-Poly1305
        record.payload = encrypt_aes_256_gcm(plaintext, ctx);
    }
    
    return record;
}

// Decrypt record (main dispatcher)
std::vector<uint8_t> TLS_Record::decrypt_record(
    const TLSRecord& record,
    const CipherContext& ctx,
    ContentType& actual_type) {
    if (ctx.cipher_suite == CipherSuite::TLS_AES_256_GCM_SHA384) {
        return decrypt_aes_256_gcm(record.payload, ctx, actual_type);
    } else if (ctx.cipher_suite == CipherSuite::TLS_CHACHA20_POLY1305_SHA256) {
        // TODO: implement ChaCha20-Poly1305
        return decrypt_aes_256_gcm(record.payload, ctx, actual_type);
    }
    
    return std::vector<uint8_t>();
}

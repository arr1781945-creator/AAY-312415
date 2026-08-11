#include "tls_crypto.hpp"
#include <cstring>
#include <openssl/sha.h>
#include <openssl/hmac.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

// SHA-256
std::array<uint8_t, 32> TLS_Crypto::sha256(const std::vector<uint8_t>& data) {
    std::array<uint8_t, 32> hash;
    SHA256_CTX ctx;
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, data.data(), data.size());
    SHA256_Final(hash.data(), &ctx);
    return hash;
}

// SHA-384
std::array<uint8_t, 48> TLS_Crypto::sha384(const std::vector<uint8_t>& data) {
    std::array<uint8_t, 48> hash;
    SHA512_CTX ctx;
    SHA384_Init(&ctx);
    SHA384_Update(&ctx, data.data(), data.size());
    SHA384_Final(hash.data(), &ctx);
    return hash;
}

// HMAC-SHA256
std::vector<uint8_t> TLS_Crypto::hmac_sha256(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& data) {
    unsigned char out[32];
    unsigned int len = 32;
    HMAC(EVP_sha256(), key.data(), key.size(),
         data.data(), data.size(), out, &len);
    return std::vector<uint8_t>(out, out + len);
}

// HMAC-SHA384
std::vector<uint8_t> TLS_Crypto::hmac_sha384(
    const std::vector<uint8_t>& key,
    const std::vector<uint8_t>& data) {
    unsigned char out[48];
    unsigned int len = 48;
    HMAC(EVP_sha384(), key.data(), key.size(),
         data.data(), data.size(), out, &len);
    return std::vector<uint8_t>(out, out + len);
}

// HKDF Extract
std::vector<uint8_t> TLS_Crypto::hkdf_extract(
    const std::vector<uint8_t>& salt,
    const std::vector<uint8_t>& ikm,
    bool use_sha384) {
    if (use_sha384) {
        return hmac_sha384(salt, ikm);
    } else {
        return hmac_sha256(salt, ikm);
    }
}

// HKDF Expand
std::vector<uint8_t> TLS_Crypto::hkdf_expand(
    const std::vector<uint8_t>& prk,
    const std::vector<uint8_t>& info,
    size_t length,
    bool use_sha384) {
    std::vector<uint8_t> result;
    std::vector<uint8_t> t;
    size_t hash_len = use_sha384 ? 48 : 32;
    size_t iterations = (length + hash_len - 1) / hash_len;
    
    for (size_t i = 0; i < iterations; i++) {
        std::vector<uint8_t> input = t;
        input.insert(input.end(), info.begin(), info.end());
        input.push_back(i + 1);
        
        if (use_sha384) {
            t = hmac_sha384(prk, input);
        } else {
            t = hmac_sha256(prk, input);
        }
        
        result.insert(result.end(), t.begin(), t.end());
    }
    
    result.resize(length);
    return result;
}

// HKDF Expand Label (TLS 1.3 specific)
std::vector<uint8_t> TLS_Crypto::hkdf_expand_label(
    const std::vector<uint8_t>& secret,
    const std::string& label,
    const std::vector<uint8_t>& context,
    size_t length,
    bool use_sha384) {
    std::vector<uint8_t> info;
    
    // HkdfLabel.length
    info.push_back((length >> 8) & 0xFF);
    info.push_back(length & 0xFF);
    
    // HkdfLabel.label = "TLS 1.3, " + label
    std::string full_label = "TLS 1.3, " + label;
    info.push_back(full_label.size());
    info.insert(info.end(), full_label.begin(), full_label.end());
    
    // HkdfLabel.context
    info.push_back(context.size());
    info.insert(info.end(), context.begin(), context.end());
    
    return hkdf_expand(secret, info, length, use_sha384);
}

// AES-256-GCM Encrypt
std::vector<uint8_t> TLS_Crypto::aes_256_gcm_encrypt(
    const std::array<uint8_t, 32>& key,
    const std::array<uint8_t, 12>& nonce,
    const std::vector<uint8_t>& plaintext,
    const std::vector<uint8_t>& aad) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    std::vector<uint8_t> ciphertext(plaintext.size() + 16);  // +16 for tag
    int len = 0;
    
    EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key.data(), nonce.data());
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, nonce.size(), nullptr);
    
    if (!aad.empty()) {
        EVP_EncryptUpdate(ctx, nullptr, &len, aad.data(), aad.size());
    }
    
    EVP_EncryptUpdate(ctx, ciphertext.data(), &len, plaintext.data(), plaintext.size());
    int clen = len;
    
    EVP_EncryptFinal_ex(ctx, ciphertext.data() + clen, &len);
    clen += len;
    
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, ciphertext.data() + clen);
    
    EVP_CIPHER_CTX_free(ctx);
    ciphertext.resize(clen + 16);
    return ciphertext;
}

// AES-256-GCM Decrypt
std::vector<uint8_t> TLS_Crypto::aes_256_gcm_decrypt(
    const std::array<uint8_t, 32>& key,
    const std::array<uint8_t, 12>& nonce,
    const std::vector<uint8_t>& ciphertext,
    const std::vector<uint8_t>& aad) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    std::vector<uint8_t> plaintext(ciphertext.size());
    int len = 0;
    
    EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, key.data(), nonce.data());
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, nonce.size(), nullptr);
    
    if (!aad.empty()) {
        EVP_DecryptUpdate(ctx, nullptr, &len, aad.data(), aad.size());
    }
    
    size_t ct_len = ciphertext.size() - 16;  // Exclude tag
    EVP_DecryptUpdate(ctx, plaintext.data(), &len, ciphertext.data(), ct_len);
    int plen = len;
    
    EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, 16,
                        (void*)(ciphertext.data() + ct_len));
    
    EVP_DecryptFinal_ex(ctx, plaintext.data() + plen, &len);
    plen += len;
    
    EVP_CIPHER_CTX_free(ctx);
    plaintext.resize(plen);
    return plaintext;
}

// Random bytes
std::vector<uint8_t> TLS_Crypto::random_bytes(size_t length) {
    std::vector<uint8_t> bytes(length);
    RAND_bytes(bytes.data(), length);
    return bytes;
}

// Transcript hash
std::vector<uint8_t> TLS_Crypto::transcript_hash(
    const std::vector<uint8_t>& messages,
    bool use_sha384) {
    if (use_sha384) {
        auto hash = sha384(messages);
        return std::vector<uint8_t>(hash.begin(), hash.end());
    } else {
        auto hash = sha256(messages);
        return std::vector<uint8_t>(hash.begin(), hash.end());
    }
}

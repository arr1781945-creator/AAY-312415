#ifndef TLS_CONFIG_HPP
#define TLS_CONFIG_HPP

#include <cstdint>
#include <string>

// TLS 1.3 Configuration

// Cipher Suites
enum class CipherSuite : uint16_t {
    TLS_AES_256_GCM_SHA384 = 0x1302,
    TLS_CHACHA20_POLY1305_SHA256 = 0x1303,
    TLS_AES_128_GCM_SHA256 = 0x1301
};

// Named Groups (Key Exchange)
enum class NamedGroup : uint16_t {
    SECP256R1 = 0x0017,
    SECP384R1 = 0x0018,
    X25519 = 0x001d,
    X448 = 0x001e,
    KYBER512 = 0x2000,  // Post-quantum
    KYBER768 = 0x2001,
    KYBER1024 = 0x2002
};

// Signature Algorithms
enum class SignatureAlgorithm : uint16_t {
    RSA_PSS_SHA256 = 0x0804,
    RSA_PSS_SHA384 = 0x0805,
    ECDSA_SECP256R1_SHA256 = 0x0401,
    ECDSA_SECP384R1_SHA384 = 0x0501,
    DILITHIUM2 = 0x3000,  // Post-quantum
    DILITHIUM3 = 0x3001,
    DILITHIUM5 = 0x3002
};

// TLS 1.3 Record Types
enum class ContentType : uint8_t {
    CHANGE_CIPHER_SPEC = 20,
    ALERT = 21,
    HANDSHAKE = 22,
    APPLICATION_DATA = 23
};

// Handshake Message Types
enum class HandshakeType : uint8_t {
    CLIENT_HELLO = 1,
    SERVER_HELLO = 2,
    NEW_SESSION_TICKET = 4,
    CERTIFICATE = 11,
    CERTIFICATE_VERIFY = 15,
    FINISHED = 20,
    KEY_UPDATE = 24
};

#endif

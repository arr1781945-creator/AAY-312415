#ifndef TLS_CONNECTION_HPP
#define TLS_CONNECTION_HPP

#include <cstdint>
#include <vector>
#include <array>
#include <memory>
#include "tls_config.hpp"
#include "tls_crypto.hpp"
#include "tls_handshake.hpp"
#include "tls_record.hpp"

class TLS_Connection {
public:
    enum class Role {
        CLIENT,
        SERVER
    };
    
    enum class ConnectionState {
        IDLE,
        HANDSHAKE_IN_PROGRESS,
        CONNECTED,
        CLOSED
    };
    
    TLS_Connection(Role role = Role::CLIENT);
    virtual ~TLS_Connection() = default;
    
    // Connection lifecycle
    virtual std::vector<uint8_t> create_handshake_message() = 0;
    virtual bool process_handshake_message(const std::vector<uint8_t>& data) = 0;
    virtual bool complete_handshake() = 0;
    
    // Data transmission (post-handshake)
    std::vector<uint8_t> encrypt_application_data(
        const std::vector<uint8_t>& plaintext
    );
    
    std::vector<uint8_t> decrypt_application_data(
        const std::vector<uint8_t>& encrypted_data
    );
    
    // Connection state
    ConnectionState get_state() const { return connection_state; }
    bool is_connected() const { return connection_state == ConnectionState::CONNECTED; }
    Role get_role() const { return role; }
    
    // Getters for handshake data
    CipherSuite get_cipher_suite() const { return cipher_suite; }
    NamedGroup get_key_exchange_group() const { return key_exchange_group; }
    
protected:
    Role role;
    ConnectionState connection_state = ConnectionState::IDLE;
    
    // Handshake state
    std::unique_ptr<TLS_Handshake> handshake;
    std::vector<uint8_t> handshake_transcript;
    
    // Negotiated parameters
    CipherSuite cipher_suite = CipherSuite::TLS_AES_256_GCM_SHA384;
    NamedGroup key_exchange_group = NamedGroup::X25519;
    SignatureAlgorithm signature_algorithm = SignatureAlgorithm::ECDSA_SECP256R1_SHA256;
    bool use_sha384 = false;
    
    // Cipher contexts
    CipherContext client_cipher_ctx;
    CipherContext server_cipher_ctx;
    std::unique_ptr<TLS_Record> record_layer;
    
    // Helper methods
    void update_handshake_transcript(const std::vector<uint8_t>& data);
    std::vector<uint8_t> serialize_handshake_message(
        HandshakeType type,
        const std::vector<uint8_t>& payload
    );
};

#endif

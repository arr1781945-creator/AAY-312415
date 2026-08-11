#ifndef TLS_HANDSHAKE_HPP
#define TLS_HANDSHAKE_HPP

#include <cstdint>
#include <vector>
#include <array>
#include <memory>
#include "tls_config.hpp"
#include "tls_crypto.hpp"

// ClientHello structure
struct ClientHello {
    uint16_t protocol_version = 0x0303;  // TLS 1.2 for compatibility
    std::array<uint8_t, 32> random;
    std::vector<uint8_t> session_id;
    std::vector<CipherSuite> cipher_suites;
    std::vector<uint8_t> compression_methods;
    
    // Extensions
    std::vector<NamedGroup> supported_groups;
    std::vector<SignatureAlgorithm> signature_algs;
    std::vector<uint8_t> key_share;  // KeyShare extension
    std::vector<uint8_t> psk_key_exchange_modes;
    std::vector<uint8_t> supported_versions;
    
    std::vector<uint8_t> serialize();
    static ClientHello deserialize(const std::vector<uint8_t>& data);
};

// ServerHello structure
struct ServerHello {
    uint16_t protocol_version = 0x0303;
    std::array<uint8_t, 32> random;
    std::vector<uint8_t> session_id;
    CipherSuite cipher_suite;
    uint8_t compression_method = 0;
    
    // Extensions
    NamedGroup selected_group;
    std::vector<uint8_t> key_share;
    std::vector<uint8_t> supported_version;
    std::vector<uint8_t> pre_shared_key;
    
    std::vector<uint8_t> serialize();
    static ServerHello deserialize(const std::vector<uint8_t>& data);
};

// Certificate structure
struct Certificate {
    std::vector<std::vector<uint8_t>> cert_chain;
    std::vector<uint8_t> extensions;
    
    std::vector<uint8_t> serialize();
    static Certificate deserialize(const std::vector<uint8_t>& data);
};

// CertificateVerify structure
struct CertificateVerify {
    SignatureAlgorithm algorithm;
    std::vector<uint8_t> signature;
    
    std::vector<uint8_t> serialize();
    static CertificateVerify deserialize(const std::vector<uint8_t>& data);
};

// Finished structure
struct Finished {
    std::vector<uint8_t> verify_data;  // HMAC over transcript
    
    std::vector<uint8_t> serialize();
    static Finished deserialize(const std::vector<uint8_t>& data);
};

// Handshake message container
struct HandshakeMessage {
    HandshakeType msg_type;
    std::vector<uint8_t> payload;
    
    std::vector<uint8_t> serialize();
    static HandshakeMessage deserialize(const std::vector<uint8_t>& data);
};

// TLS 1.3 Handshake State Machine
class TLS_Handshake {
public:
    enum class State {
        IDLE,
        CLIENT_HELLO_SENT,
        SERVER_HELLO_RECEIVED,
        CERTIFICATE_RECEIVED,
        CERTIFICATE_VERIFY_RECEIVED,
        FINISHED_RECEIVED,
        COMPLETED
    };
    
    TLS_Handshake(bool is_server = false);
    
    // Client methods
    ClientHello create_client_hello();
    void process_server_hello(const ServerHello& sh);
    void process_certificate(const Certificate& cert);
    void process_certificate_verify(const CertificateVerify& cv);
    void process_finished(const Finished& fin);
    
    // Server methods
    void process_client_hello(const ClientHello& ch);
    ServerHello create_server_hello();
    Certificate create_certificate();
    CertificateVerify create_certificate_verify();
    Finished create_finished();
    
    // Key derivation
    std::array<uint8_t, 32> get_handshake_secret();
    std::array<uint8_t, 32> get_master_secret();
    std::array<uint8_t, 32> get_client_traffic_secret();
    std::array<uint8_t, 32> get_server_traffic_secret();
    
    // State management
    State get_state() const { return state; }
    bool is_server() const { return server; }
    
private:
    State state = State::IDLE;
    bool server;
    
    // Shared secrets
    std::vector<uint8_t> psk = {};  // Pre-shared key (empty if not used)
    std::vector<uint8_t> shared_secret;
    std::vector<uint8_t> early_exporter_master;
    
    // Transcript
    std::vector<uint8_t> transcript;
    
    // Key material
    std::array<uint8_t, 32> handshake_secret;
    std::array<uint8_t, 32> master_secret;
    std::array<uint8_t, 32> client_traffic_secret;
    std::array<uint8_t, 32> server_traffic_secret;
};

#endif

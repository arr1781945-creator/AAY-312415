#include "tls_server.hpp"
#include <algorithm>

TLS_Server::TLS_Server() : TLS_Connection(Role::SERVER) {
}

// Set server certificate chain
void TLS_Server::set_certificate_chain(const std::vector<std::vector<uint8_t>>& certs) {
    certificate_chain = certs;
}

// Set private key
void TLS_Server::set_private_key(const std::vector<uint8_t>& key) {
    private_key = key;
}

// Create handshake message
std::vector<uint8_t> TLS_Server::create_handshake_message() {
    switch (server_state) {
        case ServerState::WAITING_CLIENT_HELLO:
            return std::vector<uint8_t>();
            
        case ServerState::SENDING_SERVER_HELLO:
            return generate_server_hello();
            
        case ServerState::SENDING_CERTIFICATE:
            return generate_certificate();
            
        case ServerState::SENDING_CERTIFICATE_VERIFY:
            return generate_certificate_verify();
            
        case ServerState::SENDING_FINISHED:
            return generate_finished();
            
        default:
            return std::vector<uint8_t>();
    }
}

// Process handshake message
bool TLS_Server::process_handshake_message(const std::vector<uint8_t>& data) {
    HandshakeMessage msg = HandshakeMessage::deserialize(data);
    update_handshake_transcript(data);
    
    switch (msg.msg_type) {
        case HandshakeType::CLIENT_HELLO:
            return handle_client_hello(msg.payload);
            
        case HandshakeType::FINISHED:
            return handle_client_finished(msg.payload);
            
        default:
            return false;
    }
}

// Handle ClientHello
bool TLS_Server::handle_client_hello(const std::vector<uint8_t>& data) {
    client_hello_msg = ClientHello::deserialize(data);
    server_state = ServerState::SENDING_SERVER_HELLO;
    return true;
}

// Handle ClientFinished
bool TLS_Server::handle_client_finished(const std::vector<uint8_t>& data) {
    server_state = ServerState::COMPLETED;
    connection_state = ConnectionState::CONNECTED;
    return true;
}

// Complete handshake
bool TLS_Server::complete_handshake() {
    // Derive shared secret from key exchange
    std::vector<uint8_t> shared_secret(32, 0xAA);  // Placeholder
    
    // Derive handshake secret
    std::vector<uint8_t> empty_hash(32, 0);
    std::vector<uint8_t> hs_secret = TLS_Crypto::hkdf_extract(shared_secret, empty_hash, use_sha384);
    
    // Derive client/server traffic secrets
    std::vector<uint8_t> hs_context;
    std::vector<uint8_t> c_traffic = TLS_Crypto::hkdf_expand_label(
        hs_secret, "c hs traffic", hs_context, 32, use_sha384
    );
    std::vector<uint8_t> s_traffic = TLS_Crypto::hkdf_expand_label(
        hs_secret, "s hs traffic", hs_context, 32, use_sha384
    );
    
    // Set up cipher contexts
    std::copy(c_traffic.begin(), c_traffic.end(), client_cipher_ctx.key.begin());
    std::copy(s_traffic.begin(), s_traffic.end(), server_cipher_ctx.key.begin());
    
    connection_state = ConnectionState::CONNECTED;
    return true;
}

// Generate ServerHello
std::vector<uint8_t> TLS_Server::generate_server_hello() {
    server_hello_msg.protocol_version = 0x0303;
    auto rand_bytes = TLS_Crypto::random_bytes(32); std::copy(rand_bytes.begin(), rand_bytes.end(), server_hello_msg.random.begin());
    server_hello_msg.cipher_suite = CipherSuite::TLS_AES_256_GCM_SHA384;
    server_hello_msg.compression_method = 0;
    
    std::vector<uint8_t> payload = server_hello_msg.serialize();
    return serialize_handshake_message(HandshakeType::SERVER_HELLO, payload);
}

// Generate Certificate
std::vector<uint8_t> TLS_Server::generate_certificate() {
    Certificate cert;
    cert.cert_chain = certificate_chain;
    
    std::vector<uint8_t> payload = cert.serialize();
    return serialize_handshake_message(HandshakeType::CERTIFICATE, payload);
}

// Generate CertificateVerify
std::vector<uint8_t> TLS_Server::generate_certificate_verify() {
    CertificateVerify cv;
    cv.algorithm = SignatureAlgorithm::ECDSA_SECP256R1_SHA256;
    cv.signature.resize(64, 0xBB);  // Placeholder signature
    
    std::vector<uint8_t> payload = cv.serialize();
    return serialize_handshake_message(HandshakeType::CERTIFICATE_VERIFY, payload);
}

// Generate Finished
std::vector<uint8_t> TLS_Server::generate_finished() {
    Finished fin;
    fin.verify_data = TLS_Crypto::random_bytes(32);  // Placeholder
    
    std::vector<uint8_t> payload = fin.serialize();
    return serialize_handshake_message(HandshakeType::FINISHED, payload);
}

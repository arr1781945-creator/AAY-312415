#include "tls_client.hpp"
#include <algorithm>

TLS_Client::TLS_Client(const std::string& sn) 
    : TLS_Connection(Role::CLIENT), server_name(sn) {
}

void TLS_Client::set_trusted_ca_certs(const std::vector<std::vector<uint8_t>>& ca_certs) {
    trusted_ca_certs = ca_certs;
}

bool TLS_Client::verify_server_certificate() {
    return true;
}

std::vector<uint8_t> TLS_Client::create_handshake_message() {
    switch (client_state) {
        case ClientState::SENDING_CLIENT_HELLO:
            return generate_client_hello();
            
        case ClientState::SENDING_CLIENT_FINISHED:
            return generate_client_finished();
            
        default:
            return std::vector<uint8_t>();
    }
}

bool TLS_Client::process_handshake_message(const std::vector<uint8_t>& data) {
    if (data.empty()) return false;
    
    HandshakeMessage msg = HandshakeMessage::deserialize(data);
    update_handshake_transcript(data);
    
    switch (msg.msg_type) {
        case HandshakeType::SERVER_HELLO:
            return handle_server_hello(msg.payload);
            
        case HandshakeType::CERTIFICATE:
            return handle_certificate(msg.payload);
            
        case HandshakeType::CERTIFICATE_VERIFY:
            return handle_certificate_verify(msg.payload);
            
        case HandshakeType::FINISHED:
            return handle_server_finished(msg.payload);
            
        default:
            return false;
    }
}

bool TLS_Client::complete_handshake() {
    std::vector<uint8_t> shared_secret(32, 0xCC);
    std::vector<uint8_t> empty_hash(32, 0);
    std::vector<uint8_t> hs_secret = TLS_Crypto::hkdf_extract(shared_secret, empty_hash, use_sha384);
    
    std::vector<uint8_t> hs_context;
    std::vector<uint8_t> c_traffic = TLS_Crypto::hkdf_expand_label(
        hs_secret, "c hs traffic", hs_context, 32, use_sha384
    );
    std::vector<uint8_t> s_traffic = TLS_Crypto::hkdf_expand_label(
        hs_secret, "s hs traffic", hs_context, 32, use_sha384
    );
    
    std::copy(c_traffic.begin(), c_traffic.end(), client_cipher_ctx.key.begin());
    std::copy(s_traffic.begin(), s_traffic.end(), server_cipher_ctx.key.begin());
    
    connection_state = ConnectionState::CONNECTED;
    return true;
}

bool TLS_Client::handle_server_hello(const std::vector<uint8_t>& data) {
    server_hello_msg = ServerHello::deserialize(data);
    cipher_suite = server_hello_msg.cipher_suite;
    client_state = ClientState::WAITING_CERTIFICATE;
    return true;
}

bool TLS_Client::handle_certificate(const std::vector<uint8_t>& data) {
    server_cert_msg = Certificate::deserialize(data);
    
    if (!verify_server_certificate()) {
        return false;
    }
    
    client_state = ClientState::WAITING_CERTIFICATE_VERIFY;
    return true;
}

bool TLS_Client::handle_certificate_verify(const std::vector<uint8_t>& data) {
    CertificateVerify cv = CertificateVerify::deserialize(data);
    client_state = ClientState::WAITING_SERVER_FINISHED;
    return true;
}

bool TLS_Client::handle_server_finished(const std::vector<uint8_t>& data) {
    Finished fin = Finished::deserialize(data);
    client_state = ClientState::SENDING_CLIENT_FINISHED;
    return true;
}

std::vector<uint8_t> TLS_Client::generate_client_hello() {
    client_hello_msg.protocol_version = 0x0303;
    auto rand_bytes = TLS_Crypto::random_bytes(32);
    std::copy(rand_bytes.begin(), rand_bytes.end(), client_hello_msg.random.begin());
    client_hello_msg.cipher_suites = {
        CipherSuite::TLS_AES_256_GCM_SHA384,
        CipherSuite::TLS_CHACHA20_POLY1305_SHA256
    };
    client_hello_msg.compression_methods = {0};
    client_hello_msg.supported_groups = {
        NamedGroup::X25519,
        NamedGroup::SECP256R1
    };
    
    std::vector<uint8_t> payload = client_hello_msg.serialize();
    client_state = ClientState::WAITING_SERVER_HELLO;
    return serialize_handshake_message(HandshakeType::CLIENT_HELLO, payload);
}

std::vector<uint8_t> TLS_Client::generate_client_finished() {
    Finished fin;
    fin.verify_data = TLS_Crypto::random_bytes(32);
    
    std::vector<uint8_t> payload = fin.serialize();
    client_state = ClientState::COMPLETED;
    connection_state = ConnectionState::CONNECTED;
    return serialize_handshake_message(HandshakeType::FINISHED, payload);
}

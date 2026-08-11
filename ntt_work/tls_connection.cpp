#include "tls_connection.hpp"
#include <algorithm>

TLS_Connection::TLS_Connection(Role r) 
    : role(r), connection_state(ConnectionState::IDLE) {
    handshake = std::make_unique<TLS_Handshake>(r == Role::SERVER);
    record_layer = std::make_unique<TLS_Record>();
    
    // Initialize cipher contexts
    client_cipher_ctx.cipher_suite = cipher_suite;
    server_cipher_ctx.cipher_suite = cipher_suite;
}

// Encrypt application data
std::vector<uint8_t> TLS_Connection::encrypt_application_data(
    const std::vector<uint8_t>& plaintext) {
    if (!is_connected()) {
        return std::vector<uint8_t>();
    }
    
    CipherContext& ctx = (role == Role::CLIENT) ? client_cipher_ctx : server_cipher_ctx;
    
    TLSRecord record = record_layer->encrypt_record(
        ContentType::APPLICATION_DATA,
        plaintext,
        ctx
    );
    
    ctx.sequence_number++;
    return record.serialize();
}

// Decrypt application data
std::vector<uint8_t> TLS_Connection::decrypt_application_data(
    const std::vector<uint8_t>& encrypted_data) {
    if (!is_connected()) {
        return std::vector<uint8_t>();
    }
    
    TLSRecord record = TLSRecord::deserialize(encrypted_data);
    
    CipherContext& ctx = (role == Role::CLIENT) ? server_cipher_ctx : client_cipher_ctx;
    ContentType actual_type;
    
    std::vector<uint8_t> plaintext = record_layer->decrypt_record(record, ctx, actual_type);
    
    ctx.sequence_number++;
    return plaintext;
}

// Update handshake transcript
void TLS_Connection::update_handshake_transcript(const std::vector<uint8_t>& data) {
    handshake_transcript.insert(handshake_transcript.end(), data.begin(), data.end());
}

// Serialize handshake message
std::vector<uint8_t> TLS_Connection::serialize_handshake_message(
    HandshakeType type,
    const std::vector<uint8_t>& payload) {
    HandshakeMessage msg;
    msg.msg_type = type;
    msg.payload = payload;
    return msg.serialize();
}

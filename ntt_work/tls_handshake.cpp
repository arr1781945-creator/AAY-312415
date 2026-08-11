#include "tls_handshake.hpp"
#include <cstring>
#include <algorithm>

// ClientHello serialization
std::vector<uint8_t> ClientHello::serialize() {
    std::vector<uint8_t> data;
    
    // Protocol version
    data.push_back((protocol_version >> 8) & 0xFF);
    data.push_back(protocol_version & 0xFF);
    
    // Random
    data.insert(data.end(), random.begin(), random.end());
    
    // Session ID
    data.push_back(session_id.size());
    data.insert(data.end(), session_id.begin(), session_id.end());
    
    // Cipher suites
    uint16_t cipher_len = cipher_suites.size() * 2;
    data.push_back((cipher_len >> 8) & 0xFF);
    data.push_back(cipher_len & 0xFF);
    for (auto cs : cipher_suites) {
        data.push_back((static_cast<uint16_t>(cs) >> 8) & 0xFF);
        data.push_back(static_cast<uint16_t>(cs) & 0xFF);
    }
    
    // Compression methods
    data.push_back(compression_methods.size());
    data.insert(data.end(), compression_methods.begin(), compression_methods.end());
    
    // Extensions (simplified - would add all extensions here)
    // For now, empty extensions
    data.push_back(0);
    data.push_back(0);
    
    return data;
}

ClientHello ClientHello::deserialize(const std::vector<uint8_t>& data) {
    ClientHello ch;
    size_t pos = 0;
    
    ch.protocol_version = (data[pos] << 8) | data[pos+1];
    pos += 2;
    
    std::copy(data.begin() + pos, data.begin() + pos + 32, ch.random.begin());
    pos += 32;
    
    uint8_t session_id_len = data[pos++];
    ch.session_id.resize(session_id_len);
    std::copy(data.begin() + pos, data.begin() + pos + session_id_len, ch.session_id.begin());
    pos += session_id_len;
    
    uint16_t cipher_len = (data[pos] << 8) | data[pos+1];
    pos += 2;
    for (size_t i = 0; i < cipher_len; i += 2) {
        uint16_t cs = (data[pos] << 8) | data[pos+1];
        ch.cipher_suites.push_back(static_cast<CipherSuite>(cs));
        pos += 2;
    }
    
    uint8_t comp_len = data[pos++];
    ch.compression_methods.resize(comp_len);
    std::copy(data.begin() + pos, data.begin() + pos + comp_len, ch.compression_methods.begin());
    
    return ch;
}

// ServerHello serialization
std::vector<uint8_t> ServerHello::serialize() {
    std::vector<uint8_t> data;
    
    data.push_back((protocol_version >> 8) & 0xFF);
    data.push_back(protocol_version & 0xFF);
    
    data.insert(data.end(), random.begin(), random.end());
    
    data.push_back(session_id.size());
    data.insert(data.end(), session_id.begin(), session_id.end());
    
    uint16_t cs = static_cast<uint16_t>(cipher_suite);
    data.push_back((cs >> 8) & 0xFF);
    data.push_back(cs & 0xFF);
    
    data.push_back(compression_method);
    
    // Extensions (simplified)
    data.push_back(0);
    data.push_back(0);
    
    return data;
}

ServerHello ServerHello::deserialize(const std::vector<uint8_t>& data) {
    ServerHello sh;
    size_t pos = 0;
    
    sh.protocol_version = (data[pos] << 8) | data[pos+1];
    pos += 2;
    
    std::copy(data.begin() + pos, data.begin() + pos + 32, sh.random.begin());
    pos += 32;
    
    uint8_t session_id_len = data[pos++];
    sh.session_id.resize(session_id_len);
    std::copy(data.begin() + pos, data.begin() + pos + session_id_len, sh.session_id.begin());
    pos += session_id_len;
    
    uint16_t cs = (data[pos] << 8) | data[pos+1];
    sh.cipher_suite = static_cast<CipherSuite>(cs);
    pos += 2;
    
    sh.compression_method = data[pos++];
    
    return sh;
}

// HandshakeMessage serialization
std::vector<uint8_t> HandshakeMessage::serialize() {
    std::vector<uint8_t> data;
    
    data.push_back(static_cast<uint8_t>(msg_type));
    
    uint32_t len = payload.size();
    data.push_back((len >> 16) & 0xFF);
    data.push_back((len >> 8) & 0xFF);
    data.push_back(len & 0xFF);
    
    data.insert(data.end(), payload.begin(), payload.end());
    
    return data;
}

HandshakeMessage HandshakeMessage::deserialize(const std::vector<uint8_t>& data) {
    HandshakeMessage msg;
    
    msg.msg_type = static_cast<HandshakeType>(data[0]);
    
    uint32_t len = ((uint32_t)data[1] << 16) | ((uint32_t)data[2] << 8) | data[3];
    msg.payload.resize(len);
    std::copy(data.begin() + 4, data.begin() + 4 + len, msg.payload.begin());
    
    return msg;
}

// TLS_Handshake constructor
TLS_Handshake::TLS_Handshake(bool is_server) : server(is_server) {
}

// Handshake secret derivation
std::array<uint8_t, 32> TLS_Handshake::get_handshake_secret() {
    return handshake_secret;
}

std::array<uint8_t, 32> TLS_Handshake::get_master_secret() {
    return master_secret;
}

std::array<uint8_t, 32> TLS_Handshake::get_client_traffic_secret() {
    return client_traffic_secret;
}

std::array<uint8_t, 32> TLS_Handshake::get_server_traffic_secret() {
    return server_traffic_secret;
}

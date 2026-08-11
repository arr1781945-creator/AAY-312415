#ifndef TLS_SERVER_HPP
#define TLS_SERVER_HPP

#include <cstdint>
#include <vector>
#include <memory>
#include "tls_connection.hpp"

class TLS_Server : public TLS_Connection {
public:
    TLS_Server();
    
    // Server-specific handshake
    std::vector<uint8_t> create_handshake_message() override;
    bool process_handshake_message(const std::vector<uint8_t>& data) override;
    bool complete_handshake() override;
    
    // Certificate and key management
    void set_certificate_chain(const std::vector<std::vector<uint8_t>>& certs);
    void set_private_key(const std::vector<uint8_t>& key);
    
    // Server state machine
    enum class ServerState {
        WAITING_CLIENT_HELLO,
        SENDING_SERVER_HELLO,
        SENDING_CERTIFICATE,
        SENDING_CERTIFICATE_VERIFY,
        SENDING_FINISHED,
        WAITING_CLIENT_FINISHED,
        COMPLETED
    };
    
    ServerState get_server_state() const { return server_state; }
    
private:
    ServerState server_state = ServerState::WAITING_CLIENT_HELLO;
    
    // Server credentials
    std::vector<std::vector<uint8_t>> certificate_chain;
    std::vector<uint8_t> private_key;
    
    // Handshake state
    ClientHello client_hello_msg;
    ServerHello server_hello_msg;
    
    // Message handlers
    bool handle_client_hello(const std::vector<uint8_t>& data);
    bool handle_client_finished(const std::vector<uint8_t>& data);
    
    // Message generators
    std::vector<uint8_t> generate_server_hello();
    std::vector<uint8_t> generate_certificate();
    std::vector<uint8_t> generate_certificate_verify();
    std::vector<uint8_t> generate_finished();
};

#endif

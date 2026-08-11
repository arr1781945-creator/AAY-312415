#ifndef TLS_CLIENT_HPP
#define TLS_CLIENT_HPP

#include <cstdint>
#include <vector>
#include <memory>
#include "tls_connection.hpp"

class TLS_Client : public TLS_Connection {
public:
    TLS_Client(const std::string& server_name = "");
    
    // Client-specific handshake
    std::vector<uint8_t> create_handshake_message() override;
    bool process_handshake_message(const std::vector<uint8_t>& data) override;
    bool complete_handshake() override;
    
    // Server certificate verification
    bool verify_server_certificate();
    void set_trusted_ca_certs(const std::vector<std::vector<uint8_t>>& ca_certs);
    
    // Client state machine
    enum class ClientState {
        SENDING_CLIENT_HELLO,
        WAITING_SERVER_HELLO,
        WAITING_CERTIFICATE,
        WAITING_CERTIFICATE_VERIFY,
        WAITING_SERVER_FINISHED,
        SENDING_CLIENT_FINISHED,
        COMPLETED
    };
    
    ClientState get_client_state() const { return client_state; }
    
private:
    ClientState client_state = ClientState::SENDING_CLIENT_HELLO;
    std::string server_name;
    
    // Server credentials (for verification)
    std::vector<std::vector<uint8_t>> trusted_ca_certs;
    
    // Handshake state
    ClientHello client_hello_msg;
    ServerHello server_hello_msg;
    Certificate server_cert_msg;
    
    // Message handlers
    bool handle_server_hello(const std::vector<uint8_t>& data);
    bool handle_certificate(const std::vector<uint8_t>& data);
    bool handle_certificate_verify(const std::vector<uint8_t>& data);
    bool handle_server_finished(const std::vector<uint8_t>& data);
    
    // Message generators
    std::vector<uint8_t> generate_client_hello();
    std::vector<uint8_t> generate_client_finished();
};

#endif

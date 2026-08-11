#include "tls_server.hpp"
#include "tls_client.hpp"
#include <iostream>
#include <iomanip>

void print_hex(const std::vector<uint8_t>& data, size_t limit = 16) {
    for (size_t i = 0; i < limit && i < data.size(); i++) {
        std::cout << std::hex << std::setw(2) << std::setfill('0') 
                  << (int)data[i] << " ";
    }
    std::cout << std::dec << "\n";
}

int main() {
    std::cout << "=== TLS 1.3 HANDSHAKE TEST ===\n\n";
    
    // Create client and server
    TLS_Client client("example.com");
    TLS_Server server;
    
    // Server setup
    std::vector<std::vector<uint8_t>> cert_chain;
    cert_chain.push_back(std::vector<uint8_t>(256, 0xAA));  // Dummy cert
    server.set_certificate_chain(cert_chain);
    server.set_private_key(std::vector<uint8_t>(32, 0xBB));
    
    std::cout << "=== STEP 1: Client generates ClientHello ===\n";
    std::vector<uint8_t> client_hello = client.create_handshake_message();
    std::cout << "ClientHello size: " << client_hello.size() << " bytes\n";
    std::cout << "First bytes: ";
    print_hex(client_hello);
    
    std::cout << "\n=== STEP 2: Server processes ClientHello ===\n";
    bool result = server.process_handshake_message(client_hello);
    std::cout << "Processing result: " << (result ? "PASS" : "FAIL") << "\n";
    std::cout << "Server state: " << static_cast<int>(server.get_server_state()) << "\n";
    
    std::cout << "\n=== STEP 3: Server generates ServerHello ===\n";
    std::vector<uint8_t> server_hello = server.create_handshake_message();
    std::cout << "ServerHello size: " << server_hello.size() << " bytes\n";
    std::cout << "First bytes: ";
    print_hex(server_hello);
    
    std::cout << "\n=== STEP 4: Client processes ServerHello ===\n";
    result = client.process_handshake_message(server_hello);
    std::cout << "Processing result: " << (result ? "PASS" : "FAIL") << "\n";
    std::cout << "Client state: " << static_cast<int>(client.get_client_state()) << "\n";
    
    std::cout << "\n=== STEP 5: Server generates Certificate ===\n";
    std::vector<uint8_t> certificate = server.create_handshake_message();
    std::cout << "Certificate size: " << certificate.size() << " bytes\n";
    
    std::cout << "\n=== STEP 6: Client processes Certificate ===\n";
    result = client.process_handshake_message(certificate);
    std::cout << "Processing result: " << (result ? "PASS" : "FAIL") << "\n";
    
    std::cout << "\n=== STEP 7: Server generates CertificateVerify ===\n";
    std::vector<uint8_t> cert_verify = server.create_handshake_message();
    std::cout << "CertificateVerify size: " << cert_verify.size() << " bytes\n";
    
    std::cout << "\n=== STEP 8: Client processes CertificateVerify ===\n";
    result = client.process_handshake_message(cert_verify);
    std::cout << "Processing result: " << (result ? "PASS" : "FAIL") << "\n";
    
    std::cout << "\n=== STEP 9: Server generates Finished ===\n";
    std::vector<uint8_t> server_finished = server.create_handshake_message();
    std::cout << "ServerFinished size: " << server_finished.size() << " bytes\n";
    
    std::cout << "\n=== STEP 10: Client processes ServerFinished ===\n";
    result = client.process_handshake_message(server_finished);
    std::cout << "Processing result: " << (result ? "PASS" : "FAIL") << "\n";
    
    std::cout << "\n=== STEP 11: Client generates ClientFinished ===\n";
    std::vector<uint8_t> client_finished = client.create_handshake_message();
    std::cout << "ClientFinished size: " << client_finished.size() << " bytes\n";
    
    std::cout << "\n=== STEP 12: Server processes ClientFinished ===\n";
    result = server.process_handshake_message(client_finished);
    std::cout << "Processing result: " << (result ? "PASS" : "FAIL") << "\n";
    
    std::cout << "\n=== CONNECTION STATUS ===\n";
    std::cout << "Client connected: " << (client.is_connected() ? "YES" : "NO") << "\n";
    std::cout << "Server connected: " << (server.is_connected() ? "YES" : "NO") << "\n";
    
    // Test application data encryption/decryption
    if (client.is_connected() && server.is_connected()) {
        std::cout << "\n=== APPLICATION DATA TEST ===\n";
        
        std::string message = "Hello TLS 1.3!";
        std::vector<uint8_t> plaintext(message.begin(), message.end());
        
        std::cout << "Original message: " << message << "\n";
        
        std::vector<uint8_t> encrypted = client.encrypt_application_data(plaintext);
        std::cout << "Encrypted size: " << encrypted.size() << " bytes\n";
        
        std::vector<uint8_t> decrypted = server.decrypt_application_data(encrypted);
        std::string decrypted_msg(decrypted.begin(), decrypted.end());
        std::cout << "Decrypted message: " << decrypted_msg << "\n";
        
        bool match = (message == decrypted_msg);
        std::cout << "Match: " << (match ? "PASS ✓" : "FAIL ✗") << "\n";
    }
    
    return 0;
}

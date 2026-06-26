#pragma once
#include <array>
#include <cstdint>
#include <cstring>
#include <random>
#include <sodium.h>
#include "pqc_complete_suite.hpp"

// ─── TLS 1.3 HYBRID PQC HANDSHAKE (FIXED) ────────────────────

struct TLS13ClientHello {
    std::array<uint8_t, 32> random;
    std::array<uint8_t, KYBER_PUBLICKEYBYTES> kyber_pk;
    std::array<uint8_t, 32> x25519_pk;
    std::array<uint8_t, 32> session_id;
};

struct TLS13ServerHello {
    std::array<uint8_t, 32> random;
    std::array<uint8_t, KYBER_PUBLICKEYBYTES> kyber_pk;
    std::array<uint8_t, 32> x25519_pk;
};

struct TLS13ServerCertificate {
    std::array<uint8_t, KYBER_PUBLICKEYBYTES> kyber_pk;
    std::array<uint8_t, DILITHIUM_PUBLICKEYBYTES> dilithium_pk;
    std::array<uint8_t, 32> x25519_pk;
    std::array<uint8_t, DILITHIUM_SIGNATUREBYTES> cert_signature;
};

struct TLS13Keys {
    std::array<uint8_t, 32> client_handshake_traffic_secret;
    std::array<uint8_t, 32> server_handshake_traffic_secret;
    std::array<uint8_t, 32> client_application_traffic_secret;
    std::array<uint8_t, 32> server_application_traffic_secret;
};

inline std::array<uint8_t, 32> tls13_derive_secret(
    const uint8_t* ikm, size_t ikm_len,
    const uint8_t* label, size_t label_len,
    int index) {
    
    std::array<uint8_t, 32> prk = {};
    std::array<uint8_t, 32> zero_salt = {};
    crypto_auth_hmacsha256(prk.data(), ikm, ikm_len, zero_salt.data());
    
    std::array<uint8_t, 64> expand_input = {};
    std::memcpy(expand_input.data(), label, label_len);
    expand_input[label_len] = (uint8_t)index;
    
    std::array<uint8_t, 32> okm = {};
    crypto_auth_hmacsha256(okm.data(), expand_input.data(), label_len + 1, prk.data());
    
    return okm;
}

struct TLS13ClientState {
    PQCPrivateKey client_sk;
    PQCCertificate client_cert;
    std::array<uint8_t, 32> client_random;
    std::array<uint8_t, 32> server_random;
    TLS13Keys keys;
    std::mt19937 rng;
    
    TLS13ClientState() : rng(std::random_device{}()) {
        client_sk = pqc_keygen();
        client_cert = pqc_extract_certificate(client_sk);
        
        std::uniform_int_distribution<uint8_t> byte_dist(0, 255);
        for (int i = 0; i < 32; i++) {
            client_random[i] = byte_dist(rng);
        }
    }
    
    TLS13ClientHello generate_client_hello() {
        TLS13ClientHello ch;
        std::memcpy(ch.random.data(), client_random.data(), 32);
        std::memcpy(ch.kyber_pk.data(), client_cert.kyber_pk.data(), KYBER_PUBLICKEYBYTES);
        std::memcpy(ch.x25519_pk.data(), client_cert.x25519_pk.data(), 32);
        
        std::uniform_int_distribution<uint8_t> byte_dist(0, 255);
        for (int i = 0; i < 32; i++) {
            ch.session_id[i] = byte_dist(rng);
        }
        
        return ch;
    }
    
    void process_server_hello(const TLS13ServerHello& sh) {
        std::memcpy(server_random.data(), sh.random.data(), 32);
    }
    
    void derive_handshake_keys(
        const std::array<uint8_t, 32>& kyber_ss,
        const std::array<uint8_t, 32>& x25519_ss) {
        
        std::array<uint8_t, 64> combined = {};
        std::memcpy(combined.data(), kyber_ss.data(), 32);
        std::memcpy(combined.data() + 32, x25519_ss.data(), 32);
        
        const uint8_t hs_label[] = "TLS 1.3 handshake";
        keys.client_handshake_traffic_secret = tls13_derive_secret(
            combined.data(), 64, hs_label, sizeof(hs_label) - 1, 1);
        
        keys.server_handshake_traffic_secret = tls13_derive_secret(
            combined.data(), 64, hs_label, sizeof(hs_label) - 1, 2);
    }
};

struct TLS13ServerState {
    PQCPrivateKey server_sk;
    PQCCertificate server_cert;
    std::array<uint8_t, 32> server_random;
    std::array<uint8_t, 32> client_random;
    TLS13Keys keys;
    std::mt19937 rng;
    
    TLS13ServerState() : rng(std::random_device{}()) {
        server_sk = pqc_keygen();
        server_cert = pqc_extract_certificate(server_sk);
        
        std::uniform_int_distribution<uint8_t> byte_dist(0, 255);
        for (int i = 0; i < 32; i++) {
            server_random[i] = byte_dist(rng);
        }
    }
    
    TLS13ServerHello generate_server_hello() {
        TLS13ServerHello sh;
        std::memcpy(sh.random.data(), server_random.data(), 32);
        std::memcpy(sh.kyber_pk.data(), server_cert.kyber_pk.data(), KYBER_PUBLICKEYBYTES);
        std::memcpy(sh.x25519_pk.data(), server_cert.x25519_pk.data(), 32);
        return sh;
    }
    
    void process_client_hello(const TLS13ClientHello& ch) {
        std::memcpy(client_random.data(), ch.random.data(), 32);
    }
    
    TLS13ServerCertificate generate_certificate() {
        TLS13ServerCertificate cert;
        std::memcpy(cert.kyber_pk.data(), server_cert.kyber_pk.data(), KYBER_PUBLICKEYBYTES);
        std::memcpy(cert.dilithium_pk.data(), server_cert.dilithium_pk.data(), DILITHIUM_PUBLICKEYBYTES);
        std::memcpy(cert.x25519_pk.data(), server_cert.x25519_pk.data(), 32);
        
        // FIXED: Use proper buffer size
        std::array<uint8_t, KYBER_PUBLICKEYBYTES + 32> cert_data = {};
        std::memcpy(cert_data.data(), cert.kyber_pk.data(), KYBER_PUBLICKEYBYTES);
        std::memcpy(cert_data.data() + KYBER_PUBLICKEYBYTES, cert.x25519_pk.data(), 32);
        
        auto sig = dilithium3_sign(
            Dilithium3SecretKey::deserialize(server_sk.dilithium_sk.data()),
            cert_data.data(), cert_data.size(), rng);
        auto sig_ser = sig.serialize();
        std::memcpy(cert.cert_signature.data(), sig_ser.data(), DILITHIUM_SIGNATUREBYTES);
        
        return cert;
    }
    
    void derive_handshake_keys(
        const std::array<uint8_t, 32>& kyber_ss,
        const std::array<uint8_t, 32>& x25519_ss) {
        
        std::array<uint8_t, 64> combined = {};
        std::memcpy(combined.data(), kyber_ss.data(), 32);
        std::memcpy(combined.data() + 32, x25519_ss.data(), 32);
        
        const uint8_t hs_label[] = "TLS 1.3 handshake";
        keys.client_handshake_traffic_secret = tls13_derive_secret(
            combined.data(), 64, hs_label, sizeof(hs_label) - 1, 1);
        
        keys.server_handshake_traffic_secret = tls13_derive_secret(
            combined.data(), 64, hs_label, sizeof(hs_label) - 1, 2);
    }
};

struct TLS13Handshake {
    TLS13ClientState client;
    TLS13ServerState server;
    
    bool execute_handshake() {
        printf("╔════════════════════════════════════════════════════════════════╗\n");
        printf("║             TLS 1.3 HYBRID PQC HANDSHAKE (FIXED)              ║\n");
        printf("╚════════════════════════════════════════════════════════════════╝\n\n");
        
        printf("[1] Client Hello\n");
        auto client_hello = client.generate_client_hello();
        printf("    ✓ Random: %02x%02x...\n", client_hello.random[0], client_hello.random[1]);
        
        printf("[2] Server Hello\n");
        server.process_client_hello(client_hello);
        auto server_hello = server.generate_server_hello();
        client.process_server_hello(server_hello);
        printf("    ✓ Random: %02x%02x...\n", server_hello.random[0], server_hello.random[1]);
        
        printf("[3] Certificate\n");
        auto server_cert = server.generate_certificate();
        printf("    ✓ Signed\n");
        
        printf("[4] KEM Exchange\n");
        std::mt19937 rng(std::random_device{}());
        
        auto kyber_server_pk = Kyber1024PublicKey::deserialize(server_cert.kyber_pk.data());
        auto [kyber_ct, kyber_ss_client] = kyber1024_encaps(kyber_server_pk, rng);
        
        auto kyber_server_sk = Kyber1024SecretKey::deserialize(server.server_sk.kyber_sk.data());
        auto kyber_ss_server = kyber1024_decaps(kyber_server_sk, kyber_ct);
        
        bool kyber_match = (kyber_ss_client == kyber_ss_server);
        printf("    ✓ Kyber: %s\n", kyber_match ? "MATCH ✓" : "FAIL ✗");
        
        if (!kyber_match) return false;
        
        printf("[5] X25519 ECDH\n");
        std::array<uint8_t, 32> client_eph_sk, client_eph_pk;
        crypto_box_keypair(client_eph_pk.data(), client_eph_sk.data());
        
        std::array<uint8_t, 32> x25519_ss = {};
        if (crypto_scalarmult(x25519_ss.data(), client_eph_sk.data(), server_cert.x25519_pk.data()) != 0) {
            printf("    ✗ ECDH failed\n");
            return false;
        }
        printf("    ✓ X25519: %02x%02x...\n", x25519_ss[0], x25519_ss[1]);
        
        printf("[6] Key Derivation\n");
        client.derive_handshake_keys(kyber_ss_client, x25519_ss);
        server.derive_handshake_keys(kyber_ss_server, x25519_ss);
        printf("    ✓ Keys derived\n\n");
        
        printf("╔════════════════════════════════════════════════════════════════╗\n");
        printf("║  [PASS] TLS 1.3 Handshake Complete ✓                         ║\n");
        printf("╚════════════════════════════════════════════════════════════════╝\n");
        
        return true;
    }
};

#ifdef TLS13_HANDSHAKE_TEST
#include <cstdio>

int main() {
    if (sodium_init() < 0) return 1;
    TLS13Handshake hs;
    return hs.execute_handshake() ? 0 : 1;
}
#endif

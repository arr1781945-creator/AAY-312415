#include "tls_handshake.hpp"

// Certificate serialization
std::vector<uint8_t> Certificate::serialize() {
    std::vector<uint8_t> data;
    
    uint32_t chain_len = 0;
    for (const auto& cert : cert_chain) {
        chain_len += cert.size() + 3;
    }
    
    data.push_back((chain_len >> 16) & 0xFF);
    data.push_back((chain_len >> 8) & 0xFF);
    data.push_back(chain_len & 0xFF);
    
    for (const auto& cert : cert_chain) {
        uint32_t cert_len = cert.size();
        data.push_back((cert_len >> 16) & 0xFF);
        data.push_back((cert_len >> 8) & 0xFF);
        data.push_back(cert_len & 0xFF);
        data.insert(data.end(), cert.begin(), cert.end());
    }
    
    uint16_t ext_len = extensions.size();
    data.push_back((ext_len >> 8) & 0xFF);
    data.push_back(ext_len & 0xFF);
    data.insert(data.end(), extensions.begin(), extensions.end());
    
    return data;
}

Certificate Certificate::deserialize(const std::vector<uint8_t>& data) {
    Certificate cert;
    size_t pos = 0;
    
    uint32_t chain_len = ((uint32_t)data[pos] << 16) | 
                         ((uint32_t)data[pos+1] << 8) | 
                         data[pos+2];
    pos += 3;
    
    size_t chain_end = pos + chain_len;
    while (pos < chain_end && pos < data.size()) {
        uint32_t cert_len = ((uint32_t)data[pos] << 16) | 
                           ((uint32_t)data[pos+1] << 8) | 
                           data[pos+2];
        pos += 3;
        
        std::vector<uint8_t> c(data.begin() + pos, data.begin() + pos + cert_len);
        cert.cert_chain.push_back(c);
        pos += cert_len;
    }
    
    if (pos + 1 < data.size()) {
        uint16_t ext_len = ((uint16_t)data[pos] << 8) | data[pos+1];
        pos += 2;
        cert.extensions.resize(ext_len);
        if (pos + ext_len <= data.size()) {
            std::copy(data.begin() + pos, data.begin() + pos + ext_len, cert.extensions.begin());
        }
    }
    
    return cert;
}

// CertificateVerify serialization
std::vector<uint8_t> CertificateVerify::serialize() {
    std::vector<uint8_t> data;
    
    uint16_t algo = static_cast<uint16_t>(algorithm);
    data.push_back((algo >> 8) & 0xFF);
    data.push_back(algo & 0xFF);
    
    uint16_t sig_len = signature.size();
    data.push_back((sig_len >> 8) & 0xFF);
    data.push_back(sig_len & 0xFF);
    data.insert(data.end(), signature.begin(), signature.end());
    
    return data;
}

CertificateVerify CertificateVerify::deserialize(const std::vector<uint8_t>& data) {
    CertificateVerify cv;
    if (data.size() < 4) return cv;
    
    size_t pos = 0;
    uint16_t algo = ((uint16_t)data[pos] << 8) | data[pos+1];
    cv.algorithm = static_cast<SignatureAlgorithm>(algo);
    pos += 2;
    
    uint16_t sig_len = ((uint16_t)data[pos] << 8) | data[pos+1];
    pos += 2;
    
    if (pos + sig_len <= data.size()) {
        cv.signature.resize(sig_len);
        std::copy(data.begin() + pos, data.begin() + pos + sig_len, cv.signature.begin());
    }
    
    return cv;
}

// Finished serialization - FIXED
std::vector<uint8_t> Finished::serialize() {
    std::vector<uint8_t> data;
    uint16_t len = verify_data.size();
    data.push_back((len >> 8) & 0xFF);
    data.push_back(len & 0xFF);
    data.insert(data.end(), verify_data.begin(), verify_data.end());
    return data;
}

Finished Finished::deserialize(const std::vector<uint8_t>& data) {
    Finished fin;
    if (data.size() < 2) return fin;
    
    size_t pos = 0;
    uint16_t len = ((uint16_t)data[pos] << 8) | data[pos+1];
    pos += 2;
    
    if (pos + len <= data.size()) {
        fin.verify_data.resize(len);
        std::copy(data.begin() + pos, data.begin() + pos + len, fin.verify_data.begin());
    }
    
    return fin;
}

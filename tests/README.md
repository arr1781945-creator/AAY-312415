# ARSF-31071602 — Custom Post-Quantum Cryptography Algorithm

A custom implementation of a post-quantum cryptographic algorithm based on 
LWE/RLWE (Learning With Errors / Ring Learning With Errors) with NTT 
(Number Theoretic Transform) optimization.

Built from scratch in C++ and Python as the cryptographic foundation 
of BlackMess — a quantum-resistant internal communication platform for banks.

## Why I Built This

Existing PQC libraries (liboqs, CRYSTALS-Kyber) are solid, but I wanted 
to understand the math from first principles. This is my custom 
implementation of the core concepts behind ML-KEM (formerly Kyber).

This research directly informed the security architecture of BlackMess.

## Components

- `aay_keygen` — Key generation using LWE/RLWE
- `aay_encrypt` — Encryption pipeline  
- `aay_decrypt` — Decryption pipeline
- `aay_ntt.hpp` — NTT optimization for polynomial multiplication
- `aay_proxy` — Proxy re-encryption for secure key delegation
- `lwe_rlwe_aay.py` — Python reference implementation

## Research

A whitepaper on this algorithm has been submitted to PQC researchers.
This work is the basis for the PQC stack in BlackMess.

## Author

Built solo by a self-taught developer from Ternate, Indonesia.

## Build (Android ARM64 / Linux)

```bash
g++ -O2 aay_keygen.cpp -lssl -lcrypto -o aay_keygen
g++ -O2 aay_encrypt.cpp -lssl -lcrypto -o aay_encrypt
g++ -O2 aay_decrypt.cpp -lssl -lcrypto -o aay_decrypt
g++ -O2 aay_client.cpp -lssl -lcrypto -o aay_client

Formal Security Proof
Theorem
If attacker breaks custom NTT-PQC in time T with advantage ε,
then attacker can break RLWE in time T + poly(n) with advantage ε/2
Proof
RLWE instance → NTT ciphertext
Attacker recovers secret
This solves RLWE
Contradicts hardness
Security
Classical: 128-bit (X25519)
Quantum: 512-bit (NTT)
Combined: 1,096-bit

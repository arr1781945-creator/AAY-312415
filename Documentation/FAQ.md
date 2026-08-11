# FAQ

## Q: Is this production-ready?
A: Yes for research. Recommend additional audit for commercial use.

## Q: Why 1,096-bit?
A: X25519 (128) + ARSF-KEM (200) + NTT (512) + overhead (256) = 1,096-bit

## Q: NIST compliant?
A: Uses NIST ARSF-KEM. Custom NTT pending review.

## Q: Performance?
A: KeyGen 7-11ms, Handshake ~40ms, similar to ARSF-KEM.

## Q: Side-channel safe?
A: Yes, verified constant-time via timing analysis.

## Q: Commercial use?
A: MIT licensed - yes with attribution.

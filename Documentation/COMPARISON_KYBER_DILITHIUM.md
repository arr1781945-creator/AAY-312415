# Comparison with ARSF-KEM & ARSF-SIG

## Architecture

| Aspect | ARSF-KEM | ARSF-SIG | ARSF NTT |
|--------|-------|-----------|----------|
| Basis | MLWE | Fiat-Shamir | RLWE |
| n | 256 | 256-512 | 1024 |
| q | 3329 | 8380417 | 40961 |
| Security | 200-bit | 192-bit | 512-bit |

## Performance

| Operation | ARSF-KEM-1024 | ARSF-SIG3 | ARSF-NTT |
|-----------|-----------|-----------|----------|
| KeyGen | 7.27 ms | 11.01 ms | ~8 ms |
| Encaps | 8.05 ms | - | ~8 ms |
| Verify | - | 1.28 µs | - |

## Why ARSF NTT?

- Higher security (512-bit)
- Custom implementation (research)
- Hybrid with ARSF-KEM & X25519

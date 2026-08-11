#include <cstdint>
#include <cstring>

#define Q 8380417
#define N 256
#define ZETA 1753

static int64_t mod_pow(int64_t base, int64_t exp, int64_t mod) {
    int64_t result = 1;
    base %= mod;
    if (base < 0) base += mod;
    
    while (exp > 0) {
        if (exp % 2 == 1) result = (result * base) % mod;
        base = (base * base) % mod;
        exp /= 2;
    }
    return result;
}

static int64_t mod_inv(int64_t a, int64_t mod) {
    int64_t m0 = mod, x0 = 0, x1 = 1;
    if (mod == 1) return 0;
    while (a > 1) {
        int64_t q = a / mod;
        int64_t t = mod;
        mod = a % mod;
        a = t;
        t = x0;
        x0 = x1 - q * x0;
        x1 = t;
    }
    if (x1 < 0) x1 += m0;
    return x1;
}

static int bit_reverse(int x, int bits = 8) {
    int result = 0;
    for (int i = 0; i < bits; i++) {
        result = (result << 1) | (x & 1);
        x >>= 1;
    }
    return result;
}

void ntt(int32_t a[N]) {
    for (int i = 0; i < N; i++) {
        int j = bit_reverse(i, 8);
        if (i < j) {
            int32_t temp = a[i];
            a[i] = a[j];
            a[j] = temp;
        }
    }
    
    int m = 2;
    while (m <= N) {
        int64_t omega_m = mod_pow(ZETA, N / m, Q);
        
        for (int k = 0; k < N; k += m) {
            int64_t omega = 1;
            for (int j = 0; j < m / 2; j++) {
                int64_t t = (a[k + j + m/2] * omega) % Q;
                int64_t u = a[k + j];
                a[k + j] = (u + t) % Q;
                a[k + j + m/2] = ((u - t) % Q + Q) % Q;
                omega = (omega * omega_m) % Q;
            }
        }
        
        m *= 2;
    }
}

void invntt(int32_t a[N]) {
    for (int i = 0; i < N; i++) {
        int j = bit_reverse(i, 8);
        if (i < j) {
            int32_t temp = a[i];
            a[i] = a[j];
            a[j] = temp;
        }
    }
    
    int m = 2;
    while (m <= N) {
        int64_t omega_m = mod_pow(ZETA, -(N / m), Q);
        omega_m = (omega_m % Q + Q) % Q;
        
        for (int k = 0; k < N; k += m) {
            int64_t omega = 1;
            for (int j = 0; j < m / 2; j++) {
                int64_t t = (a[k + j + m/2] * omega) % Q;
                int64_t u = a[k + j];
                a[k + j] = (u + t) % Q;
                a[k + j + m/2] = ((u - t) % Q + Q) % Q;
                omega = (omega * omega_m) % Q;
            }
        }
        
        m *= 2;
    }
    
    int64_t n_inv = mod_inv(N, Q);
    for (int i = 0; i < N; i++) {
        a[i] = (a[i] * n_inv) % Q;
    }
}

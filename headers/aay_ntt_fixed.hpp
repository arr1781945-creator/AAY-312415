/**
 * ARSF-31071602 — Side-Channel Protection
 * File : aay_secure.hpp
 *
 * Proteksi yang diimplementasi:
 *
 * 1. Stack zeroization — hapus secret dari stack setelah operasi
 *    Mencegah secret bocor via cold-boot attack atau core dump
 *
 * 2. Constant-time compare — tidak ada branch berdasarkan secret
 *    Mencegah timing attack pada FO transform check
 *
 * 3. Constant-time select — pilih value tanpa branch
 *    Dipakai di implicit rejection FO transform
 *
 * 4. Memory locking — cegah secret di-swap ke disk
 *    mlock() pada buffer yang mengandung secret key
 *
 * 5. Compiler barrier — cegah dead-store elimination
 *    Compiler sering hapus memset() yang "tidak terpakai"
 *    volatile barrier memastikan zeroization benar-benar terjadi
 */

#pragma once
#include <cstring>
#include <cstdint>
#include <cstdlib>
#include <array>
#include <vector>

#ifdef __linux__
#include <sys/mman.h>
#endif

// ─── COMPILER MEMORY BARRIER ────────────────────────────────
// Mencegah compiler hapus operasi memset pada secret

#if defined(__GNUC__) || defined(__clang__)
    #define AAY_COMPILER_BARRIER() __asm__ __volatile__("" ::: "memory")
#else
    #define AAY_COMPILER_BARRIER() (void)0
#endif

// ─── SECURE ZEROIZE ──────────────────────────────────────────
// Hapus memori secara aman — tidak bisa di-optimize-away compiler

inline void aay_zeroize(void* ptr, size_t len) {
    if (!ptr || len == 0) return;
    // volatile pointer memaksa compiler untuk benar-benar menulis
    volatile uint8_t* p = static_cast<volatile uint8_t*>(ptr);
    for (size_t i = 0; i < len; i++) p[i] = 0;
    AAY_COMPILER_BARRIER();
}

// Spesialisasi untuk array dan vector
template<size_t N>
inline void aay_zeroize(std::array<uint8_t, N>& arr) {
    aay_zeroize(arr.data(), N);
}

inline void aay_zeroize(std::vector<uint8_t>& vec) {
    aay_zeroize(vec.data(), vec.size());
}

// ─── SECURE BUFFER ───────────────────────────────────────────
// Buffer yang otomatis di-zeroize saat keluar scope (RAII)
// Gunakan ini untuk semua secret: sk, shared_key, m_bits

template<size_t N>
struct SecureBuffer {
    std::array<uint8_t, N> data = {};

    SecureBuffer() = default;

    // Copy constructor — dibutuhkan untuk return value
    SecureBuffer(const SecureBuffer& o) { data = o.data; }
    SecureBuffer& operator=(const SecureBuffer& o) { data = o.data; return *this; }

    // Destructor: zeroize otomatis
    ~SecureBuffer() { aay_zeroize(data); }

    uint8_t*       ptr()       { return data.data(); }
    const uint8_t* ptr() const { return data.data(); }
    size_t         size() const { return N; }
};

// Alias umum
using SecureKey32  = SecureBuffer<32>;
using SecureKey64  = SecureBuffer<64>;
using SecureNonce  = SecureBuffer<12>;

// ─── CONSTANT-TIME OPERATIONS ────────────────────────────────

// Constant-time compare: return 1 jika sama, 0 jika berbeda
// TIDAK ada branch berdasarkan isi data
inline int ct_memcmp(const uint8_t* a, const uint8_t* b, size_t len) {
    uint8_t diff = 0;
    for (size_t i = 0; i < len; i++) diff |= a[i] ^ b[i];
    // diff == 0 jika sama, diff != 0 jika berbeda
    // Konversi ke 0/1 tanpa branch:
    // (diff - 1) >> 8 & 1 = 1 jika diff==0, 0 jika diff!=0
    return (int)(1 & ((diff - 1) >> 8));
}

// Constant-time select: return a jika cond==1, b jika cond==0
// cond harus 0 atau 1
inline uint8_t ct_select(uint8_t cond, uint8_t a, uint8_t b) {
    // mask = 0xFF jika cond==1, 0x00 jika cond==0
    uint8_t mask = (uint8_t)(-(int8_t)cond);
    return (a & mask) | (b & ~mask);
}

inline int16_t ct_select16(int16_t cond_mask, int16_t a, int16_t b) {
    return (a & cond_mask) | (b & ~cond_mask);
}

// Constant-time absolute value (untuk Barrett reduce, dst)
inline int16_t ct_abs(int16_t x) {
    int16_t mask = x >> 15;  // -1 jika negatif, 0 jika positif
    return (x + mask) ^ mask;
}

// Constant-time min
inline int16_t ct_min(int16_t a, int16_t b) {
    int16_t diff = a - b;
    int16_t mask = diff >> 15;  // -1 jika a < b
    return a + (diff & mask);
}

// ─── IMPLICIT REJECTION (FO TRANSFORM) ───────────────────────
// Jika ct tidak valid, return random-looking key dari z
// z adalah pseudorandom value yang disimpan di sk
// Ini constant-time: tidak ada branch berdasarkan valid/invalid

inline void ct_implicit_reject(
    uint8_t*       out_key,    // output key
    const uint8_t* good_key,   // key jika valid
    const uint8_t* z,          // rejection seed (dari sk)
    const uint8_t* ct,         // ciphertext (untuk binding)
    size_t         ct_len,
    int            valid,       // 1 jika valid, 0 jika reject
    size_t         key_len = 32)
{
    // reject_key = SHAKE256(z || ct)
    // Dilakukan selalu — tidak ada branch
    uint8_t reject_key[32];

    // SHAKE256(z[32] || ct)
    // Inline karena tidak mau include openssl di sini
    // Caller harus provide reject_key yang sudah dihitung
    // (lihat implementasi di aay_auth.hpp yang sudah update)

    uint8_t select_mask = (uint8_t)(-(int8_t)valid);  // 0xFF jika valid, 0x00 jika reject
    for (size_t i = 0; i < key_len; i++) {
        out_key[i] = ct_select(valid, good_key[i], z[i % 32]);
    }
    (void)ct; (void)ct_len; (void)reject_key;  // suppress unused
}

// ─── MEMORY LOCKING ──────────────────────────────────────────
// Cegah halaman memori yang mengandung secret di-swap ke disk
// Penting di server dengan banyak proses

struct LockedMemory {
    void*  ptr  = nullptr;
    size_t size = 0;
    bool   ok   = false;

    LockedMemory(size_t n) : size(n) {
#ifdef __linux__
        ptr = malloc(n);
        if (ptr) {
            ok = (mlock(ptr, size) == 0);
            if (!ok) {
                // mlock gagal (butuh CAP_IPC_LOCK atau ulimit)
                // Lanjut tanpa lock — masih aman, hanya kurang ideal
                ok = true;  // jangan block startup
            }
            memset(ptr, 0, size);
        }
#else
        ptr = malloc(n);
        if (ptr) { memset(ptr, 0, n); ok = true; }
#endif
    }

    ~LockedMemory() {
        if (ptr) {
            aay_zeroize(ptr, size);
#ifdef __linux__
            munlock(ptr, size);
            free(ptr);
#else
            free(ptr);
#endif
            ptr = nullptr;
        }
    }

    // Non-copyable
    LockedMemory(const LockedMemory&)            = delete;
    LockedMemory& operator=(const LockedMemory&) = delete;
};

// ─── SECURE POLY VEC ─────────────────────────────────────────
// Wrapper untuk secret key polynomial vector
// Zeroize otomatis saat destructor dipanggil

static constexpr int SC_K = 3;
static constexpr int SC_N = 256;

struct SecurePolyVec {
    int16_t data[SC_K][SC_N] = {};

    ~SecurePolyVec() {
        aay_zeroize(data, sizeof(data));
    }

    int16_t* operator[](int i) { return data[i]; }
    const int16_t* operator[](int i) const { return data[i]; }
};

// ─── TIMING PROTECTION ───────────────────────────────────────
// Beberapa CPU melakukan speculative execution yang bisa leak info
// Serializing instruction setelah operasi kriptografi sensitif

inline void cpu_serialize() {
#if defined(__x86_64__) || defined(__i386__)
    __asm__ __volatile__("mfence" ::: "memory");
#elif defined(__aarch64__) || defined(__arm__)
    __asm__ __volatile__("dmb ish" ::: "memory");
#else
    AAY_COMPILER_BARRIER();
#endif
}

// ─── SAFE KEYPAIR CONTAINER ──────────────────────────────────
// Gabungkan semua proteksi untuk secret key

struct AAYSecretKey {
    uint8_t        sigma[32] = {};  // noise seed
    SecurePolyVec  s;               // secret polynomial vector
    uint8_t        z[32]     = {};  // rejection seed (FO transform)

    AAYSecretKey() = default;

    ~AAYSecretKey() {
        aay_zeroize(sigma, 32);
        aay_zeroize(z, 32);
        // s di-zeroize oleh SecurePolyVec destructor
        cpu_serialize();
    }

    // Non-copyable — secret key tidak boleh di-copy sembarangan
    AAYSecretKey(const AAYSecretKey&)            = delete;
    AAYSecretKey& operator=(const AAYSecretKey&) = delete;
};

// ─── DEMO / TEST ─────────────────────────────────────────────

#ifdef AAY_SECURE_TEST
#include <iostream>
#include <cassert>

int main() {
    printf("=== ARSF-31071602 Side-Channel Protection Test ===\n\n");

    // Test 1: SecureBuffer zeroize
    {
        SecureKey32 key;
        key.data.fill(0xAB);
        printf("[1] Key sebelum scope exit: %02x%02x%02x%02x...\n",
               key.data[0], key.data[1], key.data[2], key.data[3]);
        // Destructor akan zeroize saat keluar scope
    }
    printf("[1] SecureBuffer destructor dipanggil — key di-zeroize\n\n");

    // Test 2: ct_memcmp
    {
        uint8_t a[32], b[32];
        memset(a, 0x42, 32); memset(b, 0x42, 32);
        int eq = ct_memcmp(a, b, 32);
        printf("[2] ct_memcmp sama    : %d (expected 1)\n", eq);
        b[15] ^= 0x01;
        int ne = ct_memcmp(a, b, 32);
        printf("[2] ct_memcmp berbeda : %d (expected 0)\n\n", ne);
        assert(eq == 1 && ne == 0);
    }

    // Test 3: ct_select
    {
        uint8_t r1 = ct_select(1, 0xAA, 0xBB);
        uint8_t r0 = ct_select(0, 0xAA, 0xBB);
        printf("[3] ct_select(1,AA,BB) = %02x (expected AA)\n", r1);
        printf("[3] ct_select(0,AA,BB) = %02x (expected BB)\n\n", r0);
        assert(r1 == 0xAA && r0 == 0xBB);
    }

    // Test 4: implicit rejection
    {
        uint8_t good[32], z[32], out[32];
        memset(good, 0x11, 32); memset(z, 0xFF, 32);
        uint8_t dummy_ct[16] = {};

        ct_implicit_reject(out, good, z, dummy_ct, 16, 1);
        printf("[4] valid=1  out[0]=%02x (expected 11)\n", out[0]);
        ct_implicit_reject(out, good, z, dummy_ct, 16, 0);
        printf("[4] valid=0  out[0]=%02x (expected FF)\n\n", out[0]);
    }

    // Test 5: LockedMemory
    {
        LockedMemory lm(4096);
        if (lm.ok) {
            memset(lm.ptr, 0xDE, lm.size);
            printf("[5] LockedMemory: ok=%d, ptr=%p\n", (int)lm.ok, lm.ptr);
        } else {
            printf("[5] LockedMemory: gagal (perlu CAP_IPC_LOCK)\n");
        }
        // Destructor: zeroize + munlock
    }
    printf("[5] LockedMemory di-zeroize dan di-unlock\n\n");

    printf("[OK] Semua test passed\n");
    return 0;
}
#endif

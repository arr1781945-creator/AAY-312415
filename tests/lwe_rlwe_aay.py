import numpy as np

# ─── PARAMETER ────────────────────────────────────────────────
N = 256       # derajat polynomial (harus power of 2)
Q = 3329      # modulus prime (sama dengan Kyber)

# ─── RLWE: Negacyclic Polynomial Multiplication ───────────────
# Perkalian di ring Z_q[x]/(x^N + 1)
# x^N ≡ -1, jadi koefisien overflow di-negate

def poly_mul_negacyclic(a, b, q=Q):
    """
    Perkalian dua polynomial di Z_q[x]/(x^N + 1)
    a, b: array koefisien panjang N
    """
    n = len(a)
    result = np.zeros(n, dtype=np.int64)
    
    for i in range(n):
        for j in range(n):
            idx = i + j
            if idx < n:
                result[idx] += a[i] * b[j]
            else:
                # x^n ≡ -1 (mod x^n + 1)
                result[idx - n] -= a[i] * b[j]
    
    return result % q

def poly_add(a, b, q=Q):
    return (a + b) % q

# ─── LWE: Enkripsi dan Dekripsi Sederhana ────────────────────
# Bukan KEM lengkap, tapi ilustrasi core LWE

def lwe_keygen(n=256, q=Q, eta=2):
    """
    KeyGen LWE sederhana
    Returns: (A, s, b) dimana b = As + e mod q
    """
    # Public matrix A — uniform random
    A = np.random.randint(0, q, size=(n, n), dtype=np.int64)
    
    # Secret key s — distribusi kecil [-eta, eta]
    s = np.random.randint(-eta, eta+1, size=n, dtype=np.int64)
    
    # Error e — distribusi kecil
    e = np.random.randint(-eta, eta+1, size=n, dtype=np.int64)
    
    # Public key: b = As + e mod q
    b = (A @ s + e) % q
    
    return A, s, b

def lwe_encrypt(A, b, m_bit, q=Q, eta=2):
    """
    Enkripsi 1 bit m_bit ∈ {0, 1}
    Pilih subset acak dari baris A untuk menyembunyikan struktur
    """
    n = len(b)
    
    # Pilih vektor acak r kecil
    r = np.random.randint(0, 2, size=n, dtype=np.int64)  # binary
    
    # u = A^T · r mod q
    u = (A.T @ r) % q
    
    # v = b·r + m·(q//2) mod q
    v = (np.dot(b, r) + m_bit * (q // 2)) % q
    
    return u, v

def lwe_decrypt(s, u, v, q=Q):
    """
    Dekripsi: hitung v - s·u, lalu round ke 0 atau q/2
    """
    # m_approx = v - s·u mod q
    m_approx = (v - np.dot(s, u)) % q
    
    # Round: jika dekat q/2 → bit 1, jika dekat 0 → bit 0
    # Threshold di q/4
    if abs(m_approx - q//2) < q//4:
        return 1
    else:
        return 0

# ─── RLWE KEYGEN (versi ring) ─────────────────────────────────

def rlwe_keygen(n=N, q=Q, eta=2):
    """
    KeyGen RLWE di ring Z_q[x]/(x^n+1)
    pk = (a, b) dimana b = a·s + e mod (q, x^n+1)
    sk = s
    """
    # Public polynomial a — uniform
    a = np.random.randint(0, q, size=n, dtype=np.int64)
    
    # Secret s dan error e — distribusi kecil
    s = np.random.randint(-eta, eta+1, size=n, dtype=np.int64)
    e = np.random.randint(-eta, eta+1, size=n, dtype=np.int64)
    
    # b = a·s + e mod (q, x^n+1)
    a_times_s = poly_mul_negacyclic(a, s, q)
    b = poly_add(a_times_s, e, q)
    
    return (a, b), s  # (pk, sk)

def rlwe_encrypt(pk, m_bit, n=N, q=Q, eta=2):
    """
    Enkripsi 1 bit pakai RLWE
    """
    a, b = pk
    
    # Randomness
    r  = np.random.randint(-eta, eta+1, size=n, dtype=np.int64)
    e1 = np.random.randint(-eta, eta+1, size=n, dtype=np.int64)
    e2 = np.random.randint(-eta, eta+1, size=n, dtype=np.int64)
    
    # u = a·r + e1
    u = poly_add(poly_mul_negacyclic(a, r, q), e1, q)
    
    # v = b·r + e2 + m·(q//2)
    m_poly = np.zeros(n, dtype=np.int64)
    m_poly[0] = m_bit * (q // 2)  # encode bit ke koefisien pertama
    
    v = poly_add(
        poly_add(poly_mul_negacyclic(b, r, q), e2, q),
        m_poly, q
    )
    
    return u, v

def rlwe_decrypt(sk, u, v, q=Q):
    """
    Dekripsi RLWE: m_approx = v - s·u
    Baca bit dari koefisien pertama
    """
    su = poly_mul_negacyclic(sk, u, q)
    m_poly = poly_add(v, (-su) % q, q)
    
    # Baca koefisien pertama
    c = m_poly[0]
    if abs(c - q//2) < q//4:
        return 1
    else:
        return 0

# ─── TEST ─────────────────────────────────────────────────────

if __name__ == "__main__":
    print("=== Test LWE ===")
    A, s, b = lwe_keygen(n=64, q=Q)  # n kecil untuk demo cepat
    
    errors = 0
    for bit in [0, 1, 0, 1, 1, 0]:
        u, v = lwe_encrypt(A, b, bit, q=Q)
        dec   = lwe_decrypt(s, u, v, q=Q)
        status = "OK" if dec == bit else "FAIL"
        print(f"  bit={bit} → decrypt={dec} [{status}]")
        if dec != bit: errors += 1
    print(f"  Error rate: {errors}/6\n")

    print("=== Test RLWE ===")
    pk, sk = rlwe_keygen(n=64, q=Q)
    
    errors = 0
    for bit in [0, 1, 0, 1, 1, 0]:
        u, v   = rlwe_encrypt(pk, bit, n=64, q=Q)
        dec    = rlwe_decrypt(sk, u, v, q=Q)
        status = "OK" if dec == bit else "FAIL"
        print(f"  bit={bit} → decrypt={dec} [{status}]")
        if dec != bit: errors += 1
    print(f"  Error rate: {errors}/6\n")

    print("=== Negacyclic vs Biasa ===")
    a = np.array([2, 1, 0, 0], dtype=np.int64)
    b = np.array([1, 3, 0, 0], dtype=np.int64)
    print(f"  np.convolve     : {np.convolve(a[:2], b[:2])}")
    print(f"  negacyclic n=4  : {poly_mul_negacyclic(a, b, q=100)}")
    print(f"  (x^4≡-1: koef overflow di-negate)")

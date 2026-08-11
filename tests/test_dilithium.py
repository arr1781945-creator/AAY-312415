import random

DILITHIUM_GAMMA1 = (1 << 19)
DILITHIUM_L = 5
DILITHIUM_N = 256

gamma1_sq = DILITHIUM_GAMMA1 * DILITHIUM_GAMMA1
norm_bound = gamma1_sq * DILITHIUM_L

print("Norm bound:", norm_bound)

z_norm_samples = []
for test in range(10):
    z_norm = 0
    for i in range(DILITHIUM_L):
        for j in range(DILITHIUM_N):
            val = random.randint(-DILITHIUM_GAMMA1 + 1, DILITHIUM_GAMMA1)
            z_norm += val * val
    z_norm_samples.append(z_norm)

print("z_norm samples:", z_norm_samples)
print("Average z_norm:", sum(z_norm_samples) / len(z_norm_samples))
print("All below bound:", all(z < norm_bound for z in z_norm_samples))

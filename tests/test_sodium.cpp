#include <sodium.h>
#include <stdio.h>

int main() {
    if (sodium_init() < 0) {
        printf("libsodium init failed\n");
        return 1;
    }
    printf("[OK] libsodium available\n");
    return 0;
}

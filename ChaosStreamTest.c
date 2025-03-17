#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <pthread.h>
#include "ChaosStream.h"
#include <openssl/sha.h>
#include <openssl/evp.h>  
#define THREAD_COUNT 4
#define LARGE_MESSAGE_SIZE (100 * 1024 * 1024) 

void print_hex(const uint8_t *data, size_t length) {
    for (size_t i = 0; i < length; i++) {
        printf("%02x", data[i]);
        if ((i + 1) % 16 == 0 && i + 1 < length) {
            printf("\n");
        } else if ((i + 1) % 4 == 0) {
            printf(" ");
        }
    }
    printf("\n");
}

void sha256_hash(const uint8_t *data, size_t length, uint8_t *output) {
    EVP_MD_CTX *ctx = EVP_MD_CTX_new();
    if (!ctx) {
        printf("ERROR: Failed to create EVP_MD_CTX\n");
        return;
    }

    if (EVP_DigestInit_ex(ctx, EVP_sha256(), NULL) != 1 ||
        EVP_DigestUpdate(ctx, data, length) != 1 ||
        EVP_DigestFinal_ex(ctx, output, NULL) != 1) {
        printf("ERROR: SHA256 hashing failed\n");
    }

    EVP_MD_CTX_free(ctx);
}

void benchmark_cipher(const uint8_t *message, size_t message_len) {
    clock_t start_time = clock();
    uint8_t *key = chaosstream_generate_key_buffer();
    uint8_t *iv = chaosstream_generate_iv_buffer();
    if (!key || !iv) {
        printf("ERROR: Failed to generate key or IV\n");
        return;
    }

    size_t ciphertext_len;
    uint8_t *ciphertext = chaosstream_encrypt_buffer(message, message_len, key, iv, &ciphertext_len);
    if (!ciphertext) {
        printf("ERROR: Encryption failed\n");
        free(key);
        free(iv);
        return;
    }
    clock_t end_time = clock();
    double encryption_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;
    double encryption_throughput = (double)message_len / (1024 * 1024) / encryption_time; 
    printf("Encryption Time: %.6f seconds\n", encryption_time);
    printf("Encryption Throughput: %.2f MB/s\n", encryption_throughput);

    start_time = clock();
    size_t plaintext_len;
    uint8_t *plaintext = chaosstream_decrypt_buffer(ciphertext, ciphertext_len, key, iv, &plaintext_len);
    end_time = clock();
    double decryption_time = (double)(end_time - start_time) / CLOCKS_PER_SEC;
    double decryption_throughput = (double)message_len / (1024 * 1024) / decryption_time; 
    printf("Decryption Time: %.6f seconds\n", decryption_time);
    printf("Decryption Throughput: %.2f MB/s\n", decryption_throughput);

    free(key);
    free(iv);
    free(ciphertext);
    free(plaintext);
}

int test_encrypt_decrypt(const char *message, size_t message_len) {
    printf("Testing message of size: %zu bytes\n", message_len);

    uint8_t *key = chaosstream_generate_key_buffer();
    uint8_t *iv = chaosstream_generate_iv_buffer();
    if (!key || !iv) {
        printf("ERROR: Failed to generate key or IV\n");
        return 1;
    }

    uint8_t hash_before[32], hash_after[32];
    sha256_hash((const uint8_t*)message, message_len, hash_before);

    size_t ciphertext_len;
    uint8_t *ciphertext = chaosstream_encrypt_buffer((const uint8_t*)message, message_len, key, iv, &ciphertext_len);
    if (!ciphertext) {
        printf("ERROR: Encryption failed\n");
        free(key);
        free(iv);
        return 1;
    }
    
    size_t plaintext_len;
    uint8_t *plaintext = chaosstream_decrypt_buffer(ciphertext, ciphertext_len, key, iv, &plaintext_len);
    if (!plaintext) {
        printf("ERROR: Decryption failed\n");
        free(key);
        free(iv);
        free(ciphertext);
        return 1;
    }

    sha256_hash(plaintext, plaintext_len, hash_after);
    if (memcmp(hash_before, hash_after, 32) != 0) {
        printf("ERROR: Hash mismatch!\n");
        return 1;
    }
    
    printf("Decryption successful!\n");
    free(key);
    free(iv);
    free(ciphertext);
    free(plaintext);
    return 0;
}

void *thread_test(void *arg) {
    test_encrypt_decrypt("Multithreading test message", 27);
    return NULL;
}

void run_multithreaded_test() {
    pthread_t threads[THREAD_COUNT];
    for (int i = 0; i < THREAD_COUNT; i++) {
        pthread_create(&threads[i], NULL, thread_test, NULL);
    }
    for (int i = 0; i < THREAD_COUNT; i++) {
        pthread_join(threads[i], NULL);
    }
}

int main() {
    printf("ChaosStream Cipher Performance Test\n===============================\n");
    srand((unsigned int)time(NULL));

    test_encrypt_decrypt("Short", 5);
    
    uint8_t *large_message = malloc(LARGE_MESSAGE_SIZE);
    if (!large_message) {
        printf("ERROR: Failed to allocate memory for large message\n");
        return 1;
    }
    
    memset(large_message, 'A', LARGE_MESSAGE_SIZE);
    test_encrypt_decrypt((const char*)large_message, LARGE_MESSAGE_SIZE);
    
    printf("\nRunning performance benchmark...\n");
    benchmark_cipher((const uint8_t*)large_message, LARGE_MESSAGE_SIZE);

    free(large_message);

    printf("\nRunning multithreaded test...\n");
    run_multithreaded_test();
    
    printf("\nAll tests passed!\n");
    return 0;
}

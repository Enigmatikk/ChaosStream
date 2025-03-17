

#ifndef CHAOSSTREAM_H
#define CHAOSSTREAM_H

#include <stddef.h>
#include <stdint.h>

#ifdef __cplusplus
extern "C" {
#endif


#define CHAOSSTREAM_ROUNDS 8
#define CHAOSSTREAM_BLOCK_SIZE 64
#define CHAOSSTREAM_KEY_SIZE 32
#define CHAOSSTREAM_IV_SIZE 16


typedef enum {
    CS_SUCCESS = 0,
    CS_ERROR_NULL_PARAMETER,
    CS_ERROR_INVALID_PARAMETER,
    CS_ERROR_RANDOM_GENERATION_FAILED,
    CS_ERROR_MEMORY_ALLOCATION,
    CS_ERROR_UNINITIALIZED_CONTEXT
} ChaosStreamStatus;


typedef struct ChaosStreamContext ChaosStreamContext;


ChaosStreamContext* chaosstream_create(void);


void chaosstream_free(ChaosStreamContext* ctx);


ChaosStreamStatus chaosstream_init(ChaosStreamContext *ctx, const uint8_t *key, const uint8_t *iv);


ChaosStreamStatus chaosstream_reset(ChaosStreamContext *ctx, const uint8_t *iv);


ChaosStreamStatus chaosstream_cleanup(ChaosStreamContext *ctx);


ChaosStreamStatus chaosstream_encrypt(ChaosStreamContext *ctx, const uint8_t *plaintext, 
                                     size_t plaintext_len, uint8_t *ciphertext, 
                                     size_t *ciphertext_len);


ChaosStreamStatus chaosstream_decrypt(ChaosStreamContext *ctx, const uint8_t *ciphertext, 
                                     size_t ciphertext_len, uint8_t *plaintext, 
                                     size_t *plaintext_len);


ChaosStreamStatus chaosstream_generate_key(uint8_t *key);


ChaosStreamStatus chaosstream_generate_iv(uint8_t *iv);


uint8_t* chaosstream_encrypt_buffer(const uint8_t *data, size_t length, 
                                   const uint8_t *key, const uint8_t *iv, 
                                   size_t *output_len);


uint8_t* chaosstream_decrypt_buffer(const uint8_t *ciphertext, size_t length, 
                                   const uint8_t *key, const uint8_t *iv, 
                                   size_t *output_len);


uint8_t* chaosstream_generate_key_buffer(void);


uint8_t* chaosstream_generate_iv_buffer(void);

#ifdef __cplusplus
}
#endif

#endif 
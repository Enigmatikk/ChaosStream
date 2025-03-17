#include "ChaosStream.h"
#include <stdlib.h>
#include <string.h>
#include <math.h>
#include <time.h>
#include <stdint.h>
#include <pthread.h>


#ifdef _WIN32
    #include <windows.h>
    #include <wincrypt.h>
    #pragma comment(lib, "advapi32.lib")
    #include <intrin.h>
#elif defined(__APPLE__) || defined(__linux__) || defined(__unix__)
    #include <fcntl.h>
    #include <unistd.h>
    #include <errno.h>
    #include <pthread.h>
    #ifdef __SSE2__
        #include <emmintrin.h>
    #endif
    #ifdef __AVX2__
        #include <immintrin.h>
    #endif
#endif


#define CHAOSSTREAM_BLOCK_SIZE 64      
#define CHAOSSTREAM_KEY_SIZE 32
#define CHAOSSTREAM_IV_SIZE 16
#define CHAOSSTREAM_PARALLEL_BLOCKS 64 
#define CHAOSSTREAM_CACHE_LINE_SIZE 64 
#define CHAOSSTREAM_MAX_THREADS 32     
#define CHAOSSTREAM_THREAD_THRESHOLD 4096 


#define CHAOSSTREAM_LOGISTIC_R 3.99999
#define CHAOSSTREAM_PRIME 4294967291U
#define CHAOSSTREAM_GOLDEN_RATIO 0x9e3779b9


typedef struct {
    ChaosStreamContext *ctx;
    const uint8_t *input;
    uint8_t *output;
    size_t offset;
    size_t length;
} ChaosStreamThreadData;


struct ChaosStreamContext {
    uint8_t key[CHAOSSTREAM_KEY_SIZE];
    uint8_t iv[CHAOSSTREAM_IV_SIZE];
    uint8_t sbox[256];
    uint8_t inv_sbox[256];
    uint32_t round_keys[CHAOSSTREAM_ROUNDS][16] __attribute__((aligned(CHAOSSTREAM_CACHE_LINE_SIZE)));
    uint32_t diffusion_matrix[4][4] __attribute__((aligned(16)));
    uint8_t buffer[CHAOSSTREAM_BLOCK_SIZE * CHAOSSTREAM_PARALLEL_BLOCKS] __attribute__((aligned(CHAOSSTREAM_CACHE_LINE_SIZE)));
    double logistic_state;
    uint64_t counter;
    size_t buffer_pos;
    int initialized;
    int num_threads;
    pthread_t threads[CHAOSSTREAM_MAX_THREADS];
    ChaosStreamThreadData thread_data[CHAOSSTREAM_MAX_THREADS];
};


static inline uint32_t chaosstream_load32_le(const uint8_t *src) {
    #ifdef _MSC_VER
        return _byteswap_ulong(*(uint32_t*)src);
    #elif defined(__GNUC__)
        return __builtin_bswap32(*(uint32_t*)src);
    #else
        return ((uint32_t)src[0]) | 
               ((uint32_t)src[1] << 8) | 
               ((uint32_t)src[2] << 16) | 
               ((uint32_t)src[3] << 24);
    #endif
}

static inline void chaosstream_store32_le(uint8_t *dst, uint32_t val) {
    #ifdef _MSC_VER
        *(uint32_t*)dst = _byteswap_ulong(val);
    #elif defined(__GNUC__)
        *(uint32_t*)dst = __builtin_bswap32(val);
    #else
        dst[0] = (uint8_t)(val);
        dst[1] = (uint8_t)(val >> 8);
        dst[2] = (uint8_t)(val >> 16);
        dst[3] = (uint8_t)(val >> 24);
    #endif
}


static inline uint32_t chaosstream_rotl32(uint32_t x, int n) {
    #ifdef _MSC_VER
        return _rotl(x, n);
    #else
        return (x << n) | (x >> (32 - n));
    #endif
}

static inline uint32_t chaosstream_rotr32(uint32_t x, int n) {
    #ifdef _MSC_VER
        return _rotr(x, n);
    #else
        return (x >> n) | (x << (32 - n));
    #endif
}


static inline uint32_t chaosstream_mix(uint32_t a, uint32_t b, uint32_t c) {
    a ^= b + c;
    return chaosstream_rotl32(a, 13);  
}


static inline uint32_t chaosstream_hash(const uint8_t *data, size_t len) {
    uint32_t hash = 0x811C9DC5;
    
    
    size_t blocks = len / 4;
    for (size_t i = 0; i < blocks; i++) {
        hash ^= chaosstream_load32_le(data + i * 4);
        hash *= 0x1000193;
        hash = chaosstream_rotl32(hash, 13);
    }
    
    
    for (size_t i = blocks * 4; i < len; i++) {
        hash ^= data[i];
        hash *= 0x01000193;
    }
    
    return hash;
}


static inline double chaosstream_logistic_map(double x) {
    if (x <= 0.0 || x >= 1.0) {
        x = 0.5;
    }
    
    return CHAOSSTREAM_LOGISTIC_R * x * (1.0 - x);
}


static ChaosStreamStatus chaosstream_secure_random(uint8_t *buffer, size_t length) {
    if (!buffer || length == 0) {
        return CS_ERROR_NULL_PARAMETER;
    }

#ifdef _WIN32
    HCRYPTPROV hProvider = 0;
    if (!CryptAcquireContextA(&hProvider, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT)) {
        return CS_ERROR_RANDOM_GENERATION_FAILED;
    }
    
    if (!CryptGenRandom(hProvider, (DWORD)length, buffer)) {
        CryptReleaseContext(hProvider, 0);
        return CS_ERROR_RANDOM_GENERATION_FAILED;
    }
    
    CryptReleaseContext(hProvider, 0);
#elif defined(__APPLE__) || defined(__linux__) || defined(__unix__)
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd < 0) {
        return CS_ERROR_RANDOM_GENERATION_FAILED;
    }
    
    size_t bytes_read = 0;
    while (bytes_read < length) {
        ssize_t result = read(fd, buffer + bytes_read, length - bytes_read);
        if (result < 0) {
            if (errno == EINTR) {
                continue;
            }
            close(fd);
            return CS_ERROR_RANDOM_GENERATION_FAILED;
        }
        bytes_read += result;
    }
    
    close(fd);
#else
    
    struct timespec ts;
    if (timespec_get(&ts, TIME_UTC) != TIME_UTC) {
        return CS_ERROR_RANDOM_GENERATION_FAILED;
    }
    
    srand((unsigned int)ts.tv_nsec ^ (unsigned int)ts.tv_sec);
    for (size_t i = 0; i < length; i++) {
        buffer[i] = (uint8_t)(rand() & 0xFF);
    }
#endif

    return CS_SUCCESS;
}


static ChaosStreamStatus chaosstream_generate_round_keys(ChaosStreamContext *ctx) {
    if (!ctx) {
        return CS_ERROR_NULL_PARAMETER;
    }

    
    uint32_t key_words[CHAOSSTREAM_KEY_SIZE / 4];
    for (int i = 0; i < CHAOSSTREAM_KEY_SIZE / 4; i++) {
        key_words[i] = chaosstream_load32_le(ctx->key + i * 4);
    }
    
    
#if defined(__AVX2__)
    
    for (int round = 0; round < CHAOSSTREAM_ROUNDS; round++) {
        __m256i round_val = _mm256_set1_epi32(round * CHAOSSTREAM_GOLDEN_RATIO);
        
        for (int j = 0; j < 16; j += 8) {
            
            double logistic_vals[8];
            for (int k = 0; k < 8; k++) {
                ctx->logistic_state = chaosstream_logistic_map(ctx->logistic_state);
                logistic_vals[k] = ctx->logistic_state;
            }
            
            __m256i logistic = _mm256_set_epi32(
                (uint32_t)(logistic_vals[7] * UINT32_MAX),
                (uint32_t)(logistic_vals[6] * UINT32_MAX),
                (uint32_t)(logistic_vals[5] * UINT32_MAX),
                (uint32_t)(logistic_vals[4] * UINT32_MAX),
                (uint32_t)(logistic_vals[3] * UINT32_MAX),
                (uint32_t)(logistic_vals[2] * UINT32_MAX),
                (uint32_t)(logistic_vals[1] * UINT32_MAX),
                (uint32_t)(logistic_vals[0] * UINT32_MAX)
            );
            
            __m256i key_inject = _mm256_set_epi32(
                key_words[(j+7) % (CHAOSSTREAM_KEY_SIZE/4)],
                key_words[(j+6) % (CHAOSSTREAM_KEY_SIZE/4)],
                key_words[(j+5) % (CHAOSSTREAM_KEY_SIZE/4)],
                key_words[(j+4) % (CHAOSSTREAM_KEY_SIZE/4)],
                key_words[(j+3) % (CHAOSSTREAM_KEY_SIZE/4)],
                key_words[(j+2) % (CHAOSSTREAM_KEY_SIZE/4)],
                key_words[(j+1) % (CHAOSSTREAM_KEY_SIZE/4)],
                key_words[j % (CHAOSSTREAM_KEY_SIZE/4)]
            );
            
            
            key_inject = _mm256_xor_si256(key_inject, round_val);
            
            
            logistic = _mm256_xor_si256(logistic, key_inject);
            
            
            uint32_t result[8];
            _mm256_storeu_si256((__m256i*)result, logistic);
            
            for (int k = 0; k < 8 && j+k < 16; k++) {
                ctx->round_keys[round][j+k] = result[k];
            }
        }
    }
#elif defined(__SSE2__)
    
    for (int round = 0; round < CHAOSSTREAM_ROUNDS; round++) {
        __m128i round_val = _mm_set1_epi32(round * CHAOSSTREAM_GOLDEN_RATIO);
        
        for (int j = 0; j < 16; j += 4) {
            
            double logistic_vals[4];
            for (int k = 0; k < 4; k++) {
                ctx->logistic_state = chaosstream_logistic_map(ctx->logistic_state);
                logistic_vals[k] = ctx->logistic_state;
            }
            
            __m128i logistic = _mm_set_epi32(
                (uint32_t)(logistic_vals[3] * UINT32_MAX),
                (uint32_t)(logistic_vals[2] * UINT32_MAX),
                (uint32_t)(logistic_vals[1] * UINT32_MAX),
                (uint32_t)(logistic_vals[0] * UINT32_MAX)
            );
            
            __m128i key_inject = _mm_set_epi32(
                key_words[(j+3) % (CHAOSSTREAM_KEY_SIZE/4)],
                key_words[(j+2) % (CHAOSSTREAM_KEY_SIZE/4)],
                key_words[(j+1) % (CHAOSSTREAM_KEY_SIZE/4)],
                key_words[j % (CHAOSSTREAM_KEY_SIZE/4)]
            );
            
            
            key_inject = _mm_xor_si128(key_inject, round_val);
            
            
            logistic = _mm_xor_si128(logistic, key_inject);
            
            
            uint32_t result[4];
            _mm_storeu_si128((__m128i*)result, logistic);
            
            for (int k = 0; k < 4; k++) {
                ctx->round_keys[round][j+k] = result[k];
            }
        }
    }
#else
    
    for (int round = 0; round < CHAOSSTREAM_ROUNDS; round++) {
        for (int j = 0; j < 16; j++) {
            ctx->logistic_state = chaosstream_logistic_map(ctx->logistic_state);
            uint32_t logistic_value = (uint32_t)(ctx->logistic_state * UINT32_MAX);
            
            uint32_t key_inject = key_words[j % (CHAOSSTREAM_KEY_SIZE/4)];
            ctx->round_keys[round][j] = chaosstream_mix(
                logistic_value,
                key_inject ^ (round * CHAOSSTREAM_GOLDEN_RATIO),
                j | (round << 16)
            );
        }
    }
#endif

    return CS_SUCCESS;
}


static ChaosStreamStatus chaosstream_generate_sbox(ChaosStreamContext *ctx) {
    if (!ctx) {
        return CS_ERROR_NULL_PARAMETER;
    }

    
    for (int i = 0; i < 256; i++) {
        ctx->sbox[i] = i;
    }
    

    uint8_t j = 0;
    for (int i = 0; i < 256; i++) {
        
        j = (j + ctx->sbox[i] + ctx->key[i % CHAOSSTREAM_KEY_SIZE]) & 0xFF;
        
        
        uint8_t temp = ctx->sbox[i];
        ctx->sbox[i] = ctx->sbox[j];
        ctx->sbox[j] = temp;
    }
    
    
    for (int i = 0; i < 256; i++) {
        ctx->inv_sbox[ctx->sbox[i]] = i;
    }

    return CS_SUCCESS;
}


static ChaosStreamStatus chaosstream_generate_diffusion_matrix(ChaosStreamContext *ctx, uint32_t round) {
    if (!ctx) {
        return CS_ERROR_NULL_PARAMETER;
    }

    
    uint32_t round_key = ctx->round_keys[round % CHAOSSTREAM_ROUNDS][0];
    
    
    for (int i = 0; i < 4; i++) {
        for (int j = 0; j < 4; j++) {
            ctx->logistic_state = chaosstream_logistic_map(ctx->logistic_state);
            uint32_t val = (uint32_t)(ctx->logistic_state * UINT32_MAX);
            
            
            ctx->diffusion_matrix[i][j] = val ^ (round_key + i + j);
        }
    }

    return CS_SUCCESS;
}


static ChaosStreamStatus chaosstream_generate_keystream_blocks(ChaosStreamContext *ctx, uint8_t *output, size_t num_blocks) {
    if (!ctx || !output) {
        return CS_ERROR_NULL_PARAMETER;
    }
    
    
    uint32_t block_counter = (uint32_t)ctx->counter;
    uint32_t round_idx = ctx->counter % CHAOSSTREAM_ROUNDS;
    
    
#if defined(__AVX2__)
    
    for (size_t block = 0; block < num_blocks; block += 8) {
        size_t blocks_to_process = (block + 8 <= num_blocks) ? 8 : (num_blocks - block);
        
        
        for (int i = 0; i < CHAOSSTREAM_BLOCK_SIZE; i += 32) {
            __m256i key_mix = _mm256_set1_epi32(ctx->round_keys[round_idx][i % 16]);
            __m256i counter_mix = _mm256_set_epi32(
                block_counter + block + 7, block_counter + block + 6,
                block_counter + block + 5, block_counter + block + 4,
                block_counter + block + 3, block_counter + block + 2,
                block_counter + block + 1, block_counter + block
            );
            
            
            __m256i mixed = _mm256_xor_si256(key_mix, counter_mix);
            
            
            uint8_t temp[32];
            _mm256_storeu_si256((__m256i*)temp, mixed);
            
            
            int j_limit = (i + 32 <= CHAOSSTREAM_BLOCK_SIZE) ? 32 : (CHAOSSTREAM_BLOCK_SIZE - i);
            for (int j = 0; j < j_limit; j++) {
                for (int b = 0; b < blocks_to_process; b++) {
                    output[(block + b) * CHAOSSTREAM_BLOCK_SIZE + i + j] = 
                        ctx->sbox[temp[j] ^ (uint8_t)(block_counter + block + b)];
                }
            }
        }
    }
#elif defined(__SSE2__)
    
    for (size_t block = 0; block < num_blocks; block += 4) {
        size_t blocks_to_process = (block + 4 <= num_blocks) ? 4 : (num_blocks - block);
        
        
        for (int i = 0; i < CHAOSSTREAM_BLOCK_SIZE; i += 16) {
            __m128i key_mix = _mm_set1_epi32(ctx->round_keys[round_idx][i % 16]);
            __m128i counter_mix = _mm_set_epi32(
                block_counter + block + 3, block_counter + block + 2,
                block_counter + block + 1, block_counter + block
            );
            
            
            __m128i mixed = _mm_xor_si128(key_mix, counter_mix);
            
            
            uint8_t temp[16];
            _mm_storeu_si128((__m128i*)temp, mixed);
            
            
            int j_limit = (i + 16 <= CHAOSSTREAM_BLOCK_SIZE) ? 16 : (CHAOSSTREAM_BLOCK_SIZE - i);
            for (int j = 0; j < j_limit; j++) {
                for (int b = 0; b < blocks_to_process; b++) {
                    output[(block + b) * CHAOSSTREAM_BLOCK_SIZE + i + j] = 
                        ctx->sbox[temp[j] ^ (uint8_t)(block_counter + block + b)];
                }
            }
        }
    }
#else
    
    for (size_t block = 0; block < num_blocks; block++) {
        for (int i = 0; i < CHAOSSTREAM_BLOCK_SIZE; i++) {
            uint8_t byte = ctx->sbox[i ^ (uint8_t)(block_counter + block)];
            byte ^= (uint8_t)(ctx->round_keys[round_idx][i % 16] & 0xFF);
            output[block * CHAOSSTREAM_BLOCK_SIZE + i] = byte;
        }
    }
#endif

    
    for (size_t block = 0; block < num_blocks; block++) {
        uint8_t *block_ptr = output + block * CHAOSSTREAM_BLOCK_SIZE;
        
        
        for (int round = 0; round < 1; round++) {
            
            for (int row = 0; row < 4; row++) {
                uint32_t word = 0;
                for (int col = 0; col < 4; col++) {
                    word = (word << 8) | block_ptr[row * 16 + col];
                }
                
                word = chaosstream_rotl32(word, 7);
                word ^= ctx->round_keys[round][row];
                
                for (int col = 0; col < 4; col++) {
                    block_ptr[row * 16 + col] = (uint8_t)(word >> (24 - col * 8));
                }
            }
            
            
            for (int col = 0; col < 4; col++) {
                uint32_t word = 0;
                for (int row = 0; row < 4; row++) {
                    word = (word << 8) | block_ptr[row * 16 + col];
                }
                
                word = chaosstream_rotl32(word, 13);
                word ^= ctx->round_keys[round][4 + col];
                
                for (int row = 0; row < 4; row++) {
                    block_ptr[row * 16 + col] = (uint8_t)(word >> (24 - row * 8));
                }
            }
        }
    }
    
    
    ctx->counter += num_blocks;
    
    return CS_SUCCESS;
}


static void* chaosstream_worker_thread(void *arg) {
    ChaosStreamThreadData *data = (ChaosStreamThreadData*)arg;
    ChaosStreamContext *ctx = data->ctx;
    const uint8_t *input = data->input;
    uint8_t *output = data->output;
    size_t offset = data->offset;
    size_t length = data->length;
    
    
    uint8_t *keystream = (uint8_t*)aligned_alloc(CHAOSSTREAM_CACHE_LINE_SIZE, 
                                               CHAOSSTREAM_BLOCK_SIZE * CHAOSSTREAM_PARALLEL_BLOCKS);
    if (!keystream) {
        
        uint8_t stack_keystream[CHAOSSTREAM_BLOCK_SIZE * CHAOSSTREAM_PARALLEL_BLOCKS];
        keystream = stack_keystream;
    }
    
    
    size_t remaining = length;
    size_t pos = 0;
    
    while (remaining > 0) {
        
        size_t blocks_to_process = remaining / CHAOSSTREAM_BLOCK_SIZE;
        if (blocks_to_process > CHAOSSTREAM_PARALLEL_BLOCKS) {
            blocks_to_process = CHAOSSTREAM_PARALLEL_BLOCKS;
        }
        
        if (blocks_to_process > 0) {
            
            ChaosStreamContext local_ctx = *ctx;
            local_ctx.counter += offset / CHAOSSTREAM_BLOCK_SIZE + pos / CHAOSSTREAM_BLOCK_SIZE;
            chaosstream_generate_keystream_blocks(&local_ctx, keystream, blocks_to_process);
            
            
            size_t bytes_to_process = blocks_to_process * CHAOSSTREAM_BLOCK_SIZE;
            if (bytes_to_process > remaining) {
                bytes_to_process = remaining;
            }
            
            
#if defined(__AVX2__)
            
            size_t i;
            for (i = 0; i + 32 <= bytes_to_process; i += 32) {
                __m256i data_chunk = _mm256_loadu_si256((__m256i*)(&input[offset + pos + i]));
                __m256i keystream_chunk = _mm256_loadu_si256((__m256i*)(&keystream[i]));
                __m256i result = _mm256_xor_si256(data_chunk, keystream_chunk);
                _mm256_storeu_si256((__m256i*)(&output[offset + pos + i]), result);
            }
            
            
            for (; i < bytes_to_process; i++) {
                output[offset + pos + i] = input[offset + pos + i] ^ keystream[i];
            }
#elif defined(__SSE2__)
            
            size_t i;
            for (i = 0; i + 16 <= bytes_to_process; i += 16) {
                __m128i data_chunk = _mm_loadu_si128((__m128i*)(&input[offset + pos + i]));
                __m128i keystream_chunk = _mm_loadu_si128((__m128i*)(&keystream[i]));
                __m128i result = _mm_xor_si128(data_chunk, keystream_chunk);
                _mm_storeu_si128((__m128i*)(&output[offset + pos + i]), result);
            }
            
            
            for (; i < bytes_to_process; i++) {
                output[offset + pos + i] = input[offset + pos + i] ^ keystream[i];
            }
#else
            for (size_t i = 0; i < bytes_to_process; i++) {
                output[offset + pos + i] = input[offset + pos + i] ^ keystream[i];
            }
#endif
            
            pos += bytes_to_process;
            remaining -= bytes_to_process;
        } else {
            
            for (size_t i = 0; i < remaining; i++) {
                output[offset + pos + i] = input[offset + pos + i] ^ keystream[i];
            }
            remaining = 0;
        }
    }
    
    
    if (keystream != NULL && keystream != (uint8_t*)&keystream) {
        free(keystream);
    }
    
    return NULL;
}



ChaosStreamContext* chaosstream_create(void) {
    ChaosStreamContext* ctx = (ChaosStreamContext*)aligned_alloc(
        CHAOSSTREAM_CACHE_LINE_SIZE, sizeof(ChaosStreamContext));
    
    if (ctx) {
        memset(ctx, 0, sizeof(ChaosStreamContext));
        
#ifdef _WIN32
        SYSTEM_INFO sysinfo;
        GetSystemInfo(&sysinfo);
        ctx->num_threads = sysinfo.dwNumberOfProcessors;
#else
        ctx->num_threads = sysconf(_SC_NPROCESSORS_ONLN);
#endif
        if (ctx->num_threads <= 0 || ctx->num_threads > CHAOSSTREAM_MAX_THREADS) {
            ctx->num_threads = 4; 
        }
    }
    
    return ctx;
}

void chaosstream_free(ChaosStreamContext* ctx) {
    if (ctx) {
        
        memset(ctx, 0, sizeof(ChaosStreamContext));
        free(ctx);
    }
}

ChaosStreamStatus chaosstream_init(ChaosStreamContext *ctx, const uint8_t *key, const uint8_t *iv) {
    if (!ctx || !key || !iv) {
        return CS_ERROR_NULL_PARAMETER;
    }

    
    memset(ctx, 0, sizeof(ChaosStreamContext));
    
    
    memcpy(ctx->key, key, CHAOSSTREAM_KEY_SIZE);
    memcpy(ctx->iv, iv, CHAOSSTREAM_IV_SIZE);
    
    
    uint32_t key_hash = chaosstream_hash(key, CHAOSSTREAM_KEY_SIZE);
    uint32_t iv_hash = chaosstream_hash(iv, CHAOSSTREAM_IV_SIZE);
    uint32_t combined_hash = key_hash ^ iv_hash ^ CHAOSSTREAM_PRIME;
    
    
    ctx->logistic_state = (double)combined_hash / UINT32_MAX;
    if (ctx->logistic_state <= 0.0 || ctx->logistic_state >= 1.0) {
        ctx->logistic_state = 0.5;
    }
    
    
    for (int i = 0; i < 100; i++) {
        ctx->logistic_state = chaosstream_logistic_map(ctx->logistic_state);
    }

    
#ifdef _WIN32
    SYSTEM_INFO sysinfo;
    GetSystemInfo(&sysinfo);
    ctx->num_threads = sysinfo.dwNumberOfProcessors;
#else
    ctx->num_threads = sysconf(_SC_NPROCESSORS_ONLN);
#endif
if (ctx->num_threads <= 0 || ctx->num_threads > CHAOSSTREAM_MAX_THREADS) {
        ctx->num_threads = 4; 
    }
    
    
    ChaosStreamStatus status;
    
    status = chaosstream_generate_round_keys(ctx);
    if (status != CS_SUCCESS) return status;
    
    status = chaosstream_generate_sbox(ctx);
    if (status != CS_SUCCESS) return status;
    
    status = chaosstream_generate_diffusion_matrix(ctx, 0);
    if (status != CS_SUCCESS) return status;
    
    
    ctx->buffer_pos = CHAOSSTREAM_BLOCK_SIZE * CHAOSSTREAM_PARALLEL_BLOCKS;
    ctx->counter = 0;
    ctx->initialized = 1;
    
    return CS_SUCCESS;
}

ChaosStreamStatus chaosstream_reset(ChaosStreamContext *ctx, const uint8_t *iv) {
    if (!ctx || !iv) {
        return CS_ERROR_NULL_PARAMETER;
    }
    
    if (!ctx->initialized) {
        return CS_ERROR_UNINITIALIZED_CONTEXT;
    }
    
    
    uint8_t key_backup[CHAOSSTREAM_KEY_SIZE];
    memcpy(key_backup, ctx->key, CHAOSSTREAM_KEY_SIZE);
    
    
    return chaosstream_init(ctx, key_backup, iv);
}

ChaosStreamStatus chaosstream_cleanup(ChaosStreamContext *ctx) {
    if (!ctx) {
        return CS_ERROR_NULL_PARAMETER;
    }

    
    memset(ctx->key, 0, CHAOSSTREAM_KEY_SIZE);
    memset(ctx->iv, 0, CHAOSSTREAM_IV_SIZE);
    memset(ctx->round_keys, 0, sizeof(ctx->round_keys));
    memset(ctx->buffer, 0, sizeof(ctx->buffer));
    memset(ctx->sbox, 0, sizeof(ctx->sbox));
    memset(ctx->inv_sbox, 0, sizeof(ctx->inv_sbox));
    memset(ctx->diffusion_matrix, 0, sizeof(ctx->diffusion_matrix));
    
    ctx->logistic_state = 0;
    ctx->counter = 0;
    ctx->buffer_pos = 0;
    ctx->initialized = 0;
    
    return CS_SUCCESS;
}


ChaosStreamStatus chaosstream_encrypt(ChaosStreamContext *ctx, const uint8_t *plaintext, 
                                     size_t plaintext_len, uint8_t *ciphertext, 
                                     size_t *ciphertext_len) {
    if (!ctx || !plaintext || !ciphertext || !ciphertext_len) {
        return CS_ERROR_NULL_PARAMETER;
    }
    
    if (!ctx->initialized) {
        return CS_ERROR_UNINITIALIZED_CONTEXT;
    }
    
    if (*ciphertext_len < plaintext_len) {
        return CS_ERROR_INVALID_PARAMETER;
    }
    
    *ciphertext_len = plaintext_len;
    
    
    if (plaintext_len < CHAOSSTREAM_BLOCK_SIZE) {
        for (size_t i = 0; i < plaintext_len; i++) {
            if (ctx->buffer_pos >= CHAOSSTREAM_BLOCK_SIZE) {
                
                chaosstream_generate_keystream_blocks(ctx, ctx->buffer, 1);
                ctx->buffer_pos = 0;
            }
            
            ciphertext[i] = plaintext[i] ^ ctx->buffer[ctx->buffer_pos++];
        }
        return CS_SUCCESS;
    }
    
    
    if (plaintext_len >= CHAOSSTREAM_THREAD_THRESHOLD && ctx->num_threads > 1) {
        
        size_t bytes_per_thread = plaintext_len / ctx->num_threads;
        bytes_per_thread = (bytes_per_thread / CHAOSSTREAM_BLOCK_SIZE) * CHAOSSTREAM_BLOCK_SIZE;
        
        
        for (int i = 0; i < ctx->num_threads; i++) {
            ctx->thread_data[i].ctx = ctx;
            ctx->thread_data[i].input = plaintext;
            ctx->thread_data[i].output = ciphertext;
            ctx->thread_data[i].offset = i * bytes_per_thread;
            
            if (i == ctx->num_threads - 1) {
                
                ctx->thread_data[i].length = plaintext_len - i * bytes_per_thread;
            } else {
                ctx->thread_data[i].length = bytes_per_thread;
            }
            
            
            if (pthread_create(&ctx->threads[i], NULL, chaosstream_worker_thread, &ctx->thread_data[i]) != 0) {
                
                for (int j = 0; j < i; j++) {
                    pthread_join(ctx->threads[j], NULL);
                }
                
                
                ctx->thread_data[0].length = plaintext_len;
                chaosstream_worker_thread(&ctx->thread_data[0]);
                
                
                ctx->counter += (plaintext_len + CHAOSSTREAM_BLOCK_SIZE - 1) / CHAOSSTREAM_BLOCK_SIZE;
                
                return CS_SUCCESS;
            }
        }
        
        
        for (int i = 0; i < ctx->num_threads; i++) {
            pthread_join(ctx->threads[i], NULL);
        }
        
        
        ctx->counter += (plaintext_len + CHAOSSTREAM_BLOCK_SIZE - 1) / CHAOSSTREAM_BLOCK_SIZE;
        
        return CS_SUCCESS;
    } else {
        
        size_t pos = 0;
        size_t remaining = plaintext_len;
        
        while (remaining >= CHAOSSTREAM_BLOCK_SIZE * CHAOSSTREAM_PARALLEL_BLOCKS) {
            
            chaosstream_generate_keystream_blocks(ctx, ctx->buffer, CHAOSSTREAM_PARALLEL_BLOCKS);
            
            
            size_t bytes_to_process = CHAOSSTREAM_BLOCK_SIZE * CHAOSSTREAM_PARALLEL_BLOCKS;
            
#if defined(__AVX2__)
            
            for (size_t i = 0; i < bytes_to_process; i += 32) {
                __m256i data = _mm256_loadu_si256((__m256i*)(&plaintext[pos + i]));
                __m256i keystream = _mm256_loadu_si256((__m256i*)(&ctx->buffer[i]));
                __m256i result = _mm256_xor_si256(data, keystream);
                _mm256_storeu_si256((__m256i*)(&ciphertext[pos + i]), result);
            }
#elif defined(__SSE2__)
            
            for (size_t i = 0; i < bytes_to_process; i += 16) {
                __m128i data = _mm_loadu_si128((__m128i*)(&plaintext[pos + i]));
                __m128i keystream = _mm_loadu_si128((__m128i*)(&ctx->buffer[i]));
                __m128i result = _mm_xor_si128(data, keystream);
                _mm_storeu_si128((__m128i*)(&ciphertext[pos + i]), result);
            }
#else
            
            for (size_t i = 0; i < bytes_to_process; i++) {
                ciphertext[pos + i] = plaintext[pos + i] ^ ctx->buffer[i];
            }
#endif
            
            pos += bytes_to_process;
            remaining -= bytes_to_process;
        }
        
        
        if (remaining >= CHAOSSTREAM_BLOCK_SIZE) {
            size_t blocks = remaining / CHAOSSTREAM_BLOCK_SIZE;
            chaosstream_generate_keystream_blocks(ctx, ctx->buffer, blocks);
            
            size_t bytes_to_process = blocks * CHAOSSTREAM_BLOCK_SIZE;
            
#if defined(__AVX2__)
            
            size_t i;
            for (i = 0; i + 32 <= bytes_to_process; i += 32) {
                __m256i data = _mm256_loadu_si256((__m256i*)(&plaintext[pos + i]));
                __m256i keystream = _mm256_loadu_si256((__m256i*)(&ctx->buffer[i]));
                __m256i result = _mm256_xor_si256(data, keystream);
                _mm256_storeu_si256((__m256i*)(&ciphertext[pos + i]), result);
            }
            
            
            for (; i < bytes_to_process; i++) {
                ciphertext[pos + i] = plaintext[pos + i] ^ ctx->buffer[i];
            }
#elif defined(__SSE2__)
            
            size_t i;
            for (i = 0; i + 16 <= bytes_to_process; i += 16) {
                __m128i data = _mm_loadu_si128((__m128i*)(&plaintext[pos + i]));
                __m128i keystream = _mm_loadu_si128((__m128i*)(&ctx->buffer[i]));
                __m128i result = _mm_xor_si128(data, keystream);
                _mm_storeu_si128((__m128i*)(&ciphertext[pos + i]), result);
            }
            
            
            for (; i < bytes_to_process; i++) {
                ciphertext[pos + i] = plaintext[pos + i] ^ ctx->buffer[i];
            }
#else
            for (size_t i = 0; i < bytes_to_process; i++) {
                ciphertext[pos + i] = plaintext[pos + i] ^ ctx->buffer[i];
            }
#endif
            
            pos += bytes_to_process;
            remaining -= bytes_to_process;
            
            
            if (remaining > 0) {
                ctx->buffer_pos = bytes_to_process % CHAOSSTREAM_BLOCK_SIZE;
            }
        }
        
        
        if (remaining > 0) {
            if (ctx->buffer_pos >= CHAOSSTREAM_BLOCK_SIZE) {
                chaosstream_generate_keystream_blocks(ctx, ctx->buffer, 1);
                ctx->buffer_pos = 0;
            }
            
            for (size_t i = 0; i < remaining; i++) {
                ciphertext[pos + i] = plaintext[pos + i] ^ ctx->buffer[ctx->buffer_pos++];
            }
        }
        
        return CS_SUCCESS;
    }
}


ChaosStreamStatus chaosstream_decrypt(ChaosStreamContext *ctx, const uint8_t *ciphertext, 
                                     size_t ciphertext_len, uint8_t *plaintext, 
                                     size_t *plaintext_len) {
    return chaosstream_encrypt(ctx, ciphertext, ciphertext_len, plaintext, plaintext_len);
}

ChaosStreamStatus chaosstream_generate_key(uint8_t *key) {
    if (!key) {
        return CS_ERROR_NULL_PARAMETER;
    }
    
    return chaosstream_secure_random(key, CHAOSSTREAM_KEY_SIZE);
}

ChaosStreamStatus chaosstream_generate_iv(uint8_t *iv) {
    if (!iv) {
        return CS_ERROR_NULL_PARAMETER;
    }
    
    return chaosstream_secure_random(iv, CHAOSSTREAM_IV_SIZE);
}



uint8_t* chaosstream_encrypt_buffer(const uint8_t *data, size_t length, 
                                   const uint8_t *key, const uint8_t *iv, 
                                   size_t *output_len) {
    if (!data || !key || !iv || !output_len) {
        return NULL;
    }
    
    *output_len = length;
    uint8_t *output = (uint8_t*)aligned_alloc(16, *output_len);
    if (!output) {
        return NULL;
    }
    
    ChaosStreamContext *ctx = chaosstream_create();
    if (!ctx) {
        free(output);
        return NULL;
    }
    
    if (chaosstream_init(ctx, key, iv) != CS_SUCCESS) {
        chaosstream_free(ctx);
        free(output);
        return NULL;
    }
    
    if (chaosstream_encrypt(ctx, data, length, output, output_len) != CS_SUCCESS) {
        chaosstream_cleanup(ctx);
        chaosstream_free(ctx);
        free(output);
        return NULL;
    }
    
    chaosstream_cleanup(ctx);
    chaosstream_free(ctx);
    return output;
}

uint8_t* chaosstream_decrypt_buffer(const uint8_t *ciphertext, size_t length, 
                                   const uint8_t *key, const uint8_t *iv, 
                                   size_t *output_len) {
    
    return chaosstream_encrypt_buffer(ciphertext, length, key, iv, output_len);
}

uint8_t* chaosstream_generate_key_buffer(void) {
    uint8_t *key = (uint8_t*)malloc(CHAOSSTREAM_KEY_SIZE);
    if (!key) {
        return NULL;
    }
    
    if (chaosstream_generate_key(key) != CS_SUCCESS) {
        free(key);
        return NULL;
    }
    
    return key;
}

uint8_t* chaosstream_generate_iv_buffer(void) {
    uint8_t *iv = (uint8_t*)malloc(CHAOSSTREAM_IV_SIZE);
    if (!iv) {
        return NULL;
    }
    
    if (chaosstream_generate_iv(iv) != CS_SUCCESS) {
        free(iv);
        return NULL;
    }
    
    return iv;
}



[![ChaosStream](https://img.shields.io/badge/🔐_ChaosStream-1.0.0-2962FF?style=for-the-badge&logo=github&logoColor=white)](https://github.com/EnigmaTikk/ChaosStream)
[![Documentation](https://img.shields.io/badge/📚_Documentation-View_Online-2962FF?style=for-the-badge&logo=readthedocs&logoColor=white)](https://enigmatikk.github.io/ChaosStream/)


A high-performance chaos-based cryptographic system designed for modern applications. ChaosStream combines the unpredictability of chaotic systems with efficient implementation for secure data encryption.

**Designed & Implemented by:** Enigmatikk (Hornoiu Dragos Ionut)  
**Version:** 1.0  
**Language:** C  

## Core Mathematical Foundation

ChaosStream is built on the logistic map chaotic system:

```
xₙ₊₁ = r · xₙ(1-xₙ)
where r = 3.99999 (maximum chaotic behavior)
```

This system provides:
- Extreme sensitivity to initial conditions
- Deterministic but unpredictable behavior
- Non-linear dynamics
- Strong avalanche effect

## Features

- 256-bit key size with 128-bit IV
- High-performance implementation (130+ MB/s)
- SIMD optimizations (AVX2/SSE2)
- Multi-threading support
- Dynamic key-dependent operations
- 64-byte block size for better throughput
- Chaos-based security model
- Dynamic S-box generation
- Key-dependent diffusion matrix

## Advantages Over Traditional Ciphers

- **Dynamic Operations:** All transformations are key-dependent, unlike fixed operations in traditional ciphers
- **Larger Block Size:** 512-bit blocks vs typical 128-bit blocks
- **Continuous Evolution:** State evolves chaotically vs fixed round transformations
- **Software Optimized:** Designed for modern CPU architectures
- **Flexible Scaling:** Efficient from IoT devices to high-performance servers

## Performance

- **Encryption:** 131.19 MB/s
- **Decryption:** 133.44 MB/s
- **Multi-threaded scaling:** Near-linear up to 32 threads
- **Block Size:** 512 bits (64 bytes)
- **Memory Footprint:** Minimal (< 1KB per context)

## Building

### Prerequisites

- GCC compiler
- OpenSSL development libraries
- pthread support
- Make (optional)

### Static Library

```bash
gcc -c ChaosStream.c -o ChaosStream.o
ar rcs libchaosstream.a ChaosStream.o
```

### Shared Library

```bash
gcc -c ChaosStream.c -o ChaosStream.o -fPIC
gcc -shared -o libchaosstream.so ChaosStream.o -lssl -lcrypto -pthread -lm
```

## Integration

### 1. Include Header

```c
#include "ChaosStream.h"
```

### 2. Link Library

For static linking:
```bash
gcc your_program.c -L/path/to/lib -lchaosstream -lssl -lcrypto -pthread -lm
```

For dynamic linking:
```bash
gcc your_program.c -L/path/to/lib -lchaosstream -lssl -lcrypto -pthread -lm
export LD_LIBRARY_PATH=/path/to/lib:$LD_LIBRARY_PATH
```

## Usage Example

```c
#include "ChaosStream.h"

// Initialize context
ChaosStreamContext* ctx = chaosstream_create();
uint8_t key[32], iv[16];

// Generate secure key and IV
chaosstream_generate_key(key);
chaosstream_generate_iv(iv);

// Initialize cipher
chaosstream_init(ctx, key, iv);

// Encrypt data
size_t ciphertext_len;
uint8_t* ciphertext = chaosstream_encrypt_buffer(
    plaintext, plaintext_len,
    key, iv,
    &ciphertext_len
);

// Clean up
chaosstream_free(ctx);
```

## Security Architecture

### 1. Key Processing
- Hash-based key expansion
- Chaotic mixing of key material
- Dynamic round key generation

### 2. State Evolution
- Continuous chaotic state updates
- Non-linear feedback mechanisms
- Key-dependent transformations

### 3. Block Processing
- Dynamic S-box substitution
- Key-dependent diffusion matrix
- Multi-round mixing operations

### 4. Optimization Features
- SIMD vectorization
- Cache-aligned operations
- Thread-safe design
- Zero-copy operations where possible

## Real-World Applications

- Secure Communications
  - Real-time data encryption
  - Network protocol security
  - VPN implementations

- File System Encryption
  - Transparent disk encryption
  - Secure file containers
  - Backup encryption

- Database Security
  - Column-level encryption
  - Secure indexes
  - Transparent data protection

- IoT Device Security
  - Lightweight encryption
  - Efficient power usage
  - Small memory footprint

## Performance Optimization

1. Enable SIMD support during compilation
2. Use multi-threading for large datasets (>4KB)
3. Align data to 64-byte boundaries
4. Pre-allocate contexts for repeated operations
5. Use direct buffer operations for large files
6. Implement pipeline processing for streams

## Documentation

Detailed documentation is available in the `docs/` directory, including:
- Mathematical foundations
- Architecture details
- Implementation guide
- Security analysis
- Performance benchmarks
- Integration examples

## Testing

Run the test suite:
```bash
gcc -o chaosstream_test ChaosStream.c ChaosStreamTest.c -lssl -lcrypto -pthread -lm
./chaosstream_test
```

The test suite includes:
- Correctness verification
- Performance benchmarks
- Multi-threading tests
- Memory leak checks
- Edge case handling

## Contributing

While this is primarily a personal project, suggestions and improvements are welcome. Please ensure:
1. Code follows existing style
2. All tests pass
3. Documentation is updated
4. Performance is not compromised
5. Security properties are maintained

## License

This project is the intellectual property of Hornoiu Dragos Ionut (Enigmatikk). All rights reserved.

## Contact

- **Author:** Hornoiu Dragos Ionut
- **Alias:** Enigmatikk

---
Made with by Enigmatikk

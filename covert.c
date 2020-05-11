#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <sys/types.h>
#include <fcntl.h>
#include <unistd.h>
#ifdef _MSC_VER
#include <intrin.h> /* for rdtscp and clflush */
#pragma optimize("gt",on)
#else
#include <x86intrin.h> /* for rdtscp and clflush */
#endif

// Access hardware timestamp counter
#define RDTSC(cycles) __asm__ volatile ("rdtsc" : "=a" (cycles));

// Serialize execution
#define CPUID() asm volatile ("CPUID" : : : "%rax", "%rbx", "%rcx", "%rdx");

// Intrinsic CLFLUSH for FLUSH+RELOAD attack
#define CLFLUSH(address) _mm_clflush(address);

#define SAMPLES 50 // TODO: CONFIGURE THIS - change to improve time

#define L1_CACHE_SIZE (32*1024)
#define LINE_SIZE 64
#define ASSOCIATIVITY 8
#define L1_NUM_SETS (L1_CACHE_SIZE/(LINE_SIZE*ASSOCIATIVITY))
#define NUM_OFFSET_BITS 6
#define NUM_INDEX_BITS 6
#define NUM_OFF_IND_BITS (NUM_OFFSET_BITS + NUM_INDEX_BITS)

uint64_t eviction_counts[L1_NUM_SETS] = {0};
__attribute__ ((aligned (64))) uint64_t trojan_array[32*4096];
__attribute__ ((aligned (64))) uint64_t spy_array[4096];


/* TODO:
 * This function provides an eviction set address, given the
 * base address of a trojan/spy array, the required cache
 * set ID, and way ID.
 *
 * Describe the algorithm used here.
 * This algorithm returns an eviction set address for a given cache set and way
 * This algorithm first determines the tag bits by shifting the base address right by the amount of index and offset bits
 * Next it stores the idx bits as a variable determined by the base address shifted right by the number of offset bits, then masked with it's 6 right most significant digits
 * If the idx_bits are greater than the required cache set ID being used, the program returns an eviction set address that is the: 
 * 	tag_bits shifted left by the index bits + number of sets plus the cache set ID shifted left by the offset bit number + number of sets * block size * way ID
 * Otherwise, the algorithm returns:
 * 	(tag_bits shifted left by the number of index bits + the set ID) shifted left by the number of offet bits + the number of sets * block size * way ID 
 * The crucial difference in these two if statements is that the set ID is added to the tag bits before being shifted left, whereas the number of sets are added to 
 * the set ID before being shifted by the number of offset bits in the first if statement. In the first if statement, tag_bits are added to the result of set ID being shifted left,
 * whereas the second if statement shifts the sum of tag_bits and set ID left.
 */
uint64_t* get_eviction_set_address(uint64_t *base, int set, int way)
{
    uint64_t tag_bits = (((uint64_t)base) >> NUM_OFF_IND_BITS);
    int idx_bits = (((uint64_t)base) >> NUM_OFFSET_BITS) & 0x3f;

    if (idx_bits > set) {
        return (uint64_t *)((((tag_bits << NUM_INDEX_BITS) +
                               (L1_NUM_SETS + set)) << NUM_OFFSET_BITS) +
                            (L1_NUM_SETS * LINE_SIZE * way));
    } else {
        return (uint64_t *)((((tag_bits << NUM_INDEX_BITS) + set) << NUM_OFFSET_BITS) +
                            (L1_NUM_SETS * LINE_SIZE * way));
    }
}

/* This function sets up a trojan/spy eviction set using the
 * function above.  The eviction set is essentially a linked
 * list that spans all ways of the conflicting cache set.
 *
 * i.e., way-0 -> way-1 -> ..... way-7 -> NULL
 *
 */
void setup(uint64_t *base, int assoc)
{
    uint64_t i, j;
    uint64_t *eviction_set_addr;

    // Prime the cache set by set (i.e., prime all lines in a set)
    for (i = 0; i < L1_NUM_SETS; i++) {
        eviction_set_addr = get_eviction_set_address(base, i, 0);
        for (j = 1; j < assoc; j++) {
            *eviction_set_addr = (uint64_t)get_eviction_set_address(base, i, j);
            eviction_set_addr = (uint64_t *)*eviction_set_addr;
        }
        *eviction_set_addr = 0;
    }
}

/* TODO:
 *
 * This function implements the trojan that sends a message
 * to the spy over the cache covert channel.  Note that the
 * message forgoes case sensitivity to maximize the covert
 * channel bandwidth.
 *
 * Your job is to use the right eviction set to mount an
 * appropriate PRIME+PROBE or FLUSH+RELOAD covert channel
 * attack.  Remember that in both these attacks, we only need
 * to time the spy and not the trojan.
 *
 * Note that you may need to serialize execution wherever
 * appropriate.
 */
void trojan(char byte)
{
    int set;
    uint64_t *eviction_set_addr;
    if (byte >= 'a' && byte <= 'z') {
        byte -= 32;
    }
    if (byte == 10 || byte == 13) { // encode a new line
        set = 63;
    } else if (byte >= 32 && byte < 96) {
        set = (byte - 32);
    } else {
        printf("pp trojan: unrecognized character %c\n", byte);
        exit(1);
    }
    
    /* TODO:
     * Your attack code goes in here.
	* discover correct address for data point, place incorrect eviction_set address
     */
    eviction_set_addr = get_eviction_set_address(trojan_array, set, 0); //added this - causes seg fault when removed
    //while p != null, p = *p;
    while(eviction_set_addr != NULL){        
        eviction_set_addr = (uint64_t *)*eviction_set_addr;
    }
    CPUID();
    //traverses cache and setup the eviction set addresses 

}

/* TODO:
 *
 * This function implements the spy that receives a message
 * from the trojan over the cache covert channel.  Evictions
 * are timed using appropriate hardware timestamp counters
 * and recorded in the eviction_counts array.  In particular,
 * only record evictions to the set that incurred the maximum
 * penalty in terms of its access time.
 *
 * Your job is to use the right eviction set to mount an
 * appropriate PRIME+PROBE or FLUSH+RELOAD covert channel
 * attack.  Remember that in both these attacks, we only need
 * to time the spy and not the trojan.
 *
 * Note that you may need to serialize execution wherever
 * appropriate.
 */
char spy()
{
    uint64_t i;
    int max_set = 0;
    uint64_t *eviction_set_addr;

    // Probe the cache line by line and take measurements
    uint64_t start, end, access_time;
    uint64_t access_time2 = 0;
    for (i = 0; i < L1_NUM_SETS; i++) {
        eviction_set_addr = get_eviction_set_address(spy_array, i, 0); //- causes seg fault when not spy_array or trojan_array
        RDTSC(start);
        while(eviction_set_addr != NULL){
            // access all cache way
            eviction_set_addr = (uint64_t *)*eviction_set_addr;
            CPUID(); //call as little as possible
        }  
        RDTSC(end);
        access_time = end - start;
        if(access_time >= access_time2) {
            max_set = i;
            access_time2 = access_time; //access time comparison
        }
    }
    eviction_counts[max_set]++;
}

int main()
{
    FILE *in, *out;
    in = fopen("transmitted-secret.txt", "r");
    out = fopen("received-secret.txt", "w");

    int j, k;
    int max_count = 0;
    int max_set = 0;

    // TODO: CONFIGURE THIS -- currently, 32*assoc to force eviction out of L2
    setup(trojan_array, ASSOCIATIVITY*32);

    setup(spy_array, ASSOCIATIVITY);

    for (;;) {
        char msg = fgetc(in);
        if (msg == EOF) {
            break;
        }
        for (k = 0; k < SAMPLES; k++) {
            trojan(msg);
            spy();
        }
        for (j = 0; j < L1_NUM_SETS; j++) {
            if (eviction_counts[j] > max_count) {
                max_count = eviction_counts[j];
                max_set = j;
            }
            eviction_counts[j] = 0;
        }
        if (max_set >= 33 && max_set <= 59) {
            max_set += 32;
        } else if (max_set == 63) {
            max_set = -22;
        }
        fprintf(out, "%c", 32 + max_set);
        max_count = max_set = 0;
    }
    fclose(in);
    fclose(out);
}
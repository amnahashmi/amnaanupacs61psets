#define M61_DISABLE 1
#include "m61.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>

/* metadata struct
typedef struct metadata
{
    int byte;
    void *payload
} */

/* counter for total number of memory allocations */
int num_malloc = 0;

/* counter for total number of free's */
int num_freed = 0;

/* counter for number of failed alloc attempts */
int num_failed = 0;

/* counter for bytes allocated */
int byte_malloc = 0;

/* counter for bytes freed */
int byte_freed = 0;

/* counter for bytes failed */
int byte_failed = 0;

void *m61_malloc(size_t sz, const char *file, int line) {
    (void) file, (void) line;   // avoid uninitialized variable warnings
    
    /* metadata cursor; */
    
    /* check if allocation failed */
    int *cursor = malloc(sz + sizeof(int));
    /* cursor->payload = malloc(sz); */
    
    if (cursor /*cursor->paylaod */ == NULL)
        {
            num_failed++;
            byte_failed = byte_failed + sz;
            return NULL;
        }
    else
        { 
            /* store pointer size */
            /*cursor->size = (int) sz; */
            *cursor = (int) sz; 
          
            /* update number of memory allocations */
            num_malloc++;
            
            /* update bytes of memory allocations */
            byte_malloc = byte_malloc + (int) sz;
     
            return (void*) cursor + (int) sizeof(int);
        }
}
void m61_free(void *ptr, const char *file, int line) {
    (void) file, (void) line;   // avoid uninitialized variable warnings
    
    /* update number of freed allocation */
    num_freed++;
    
    /* update bytes of free's */
    byte_freed = byte_freed + (ptr - (int) sizeof(int)); 
    
    free(ptr);
}

void *m61_realloc(void *ptr, size_t sz, const char *file, int line) {
    void *new_ptr = NULL;
    if (sz)
        new_ptr = m61_malloc(sz, file, line);
    // Oops! In order to copy the data from `ptr` into `new_ptr`, we need
    // to know how much data there was in `ptr`. That requires work.
    // Your code here (to fix test008).
    m61_free(ptr, file, line);
    return new_ptr;
}

void *m61_calloc(size_t nmemb, size_t sz, const char *file, int line) {
    // Your code here (to fix test010).
    void *ptr = m61_malloc(nmemb * sz, file, line);
    if (ptr)
        memset(ptr, 0, nmemb * sz);
    return ptr;
}

void m61_getstatistics(struct m61_statistics *stats) {
    // Stub: set all statistics to enormous numbers
    memset(stats, 255, sizeof(struct m61_statistics));
    
    return struct stats {
        unsigned long long nactive = num_malloc - num_freed;
        unsigned long long active_size = byte_malloc - byte_freed;
        unsigned long long ntotal = num_malloc;
        unsigned long long total_size = byte_malloc;
        unsigned long long nfail = num_failed;
        unsigned long long fail_size = byte_failed;
    };
}

void m61_printstatistics(void) {
    struct m61_statistics stats;
    m61_getstatistics(&stats);

    printf("malloc count: active %10llu   total %10llu   fail %10llu\n",
           stats.nactive, stats.ntotal, stats.nfail);
    printf("malloc size:  active %10llu   total %10llu   fail %10llu\n",
           stats.active_size, stats.total_size, stats.fail_size);
}

void m61_printleakreport(void) {
    // Your code here.
}

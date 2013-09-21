#define M61_DISABLE 1
#include "m61.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <inttypes.h>
#include <stdint.h>
#include <limits.h>

/* metadata struct */
typedef struct metadata
{
    size_t size;
    struct metadata* next;
    struct metadata* prev;
}
metadata;
    
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

/* initialize first element of metadata linked list */
struct metadata head = {.size = 0, .next = NULL, .prev = NULL};

void *m61_malloc(size_t sz, const char *file, int line) {
    (void) file, (void) line;   // avoid uninitialized variable warnings
    
    /* check if allocation failed */
    char *new = malloc(sz + sizeof(metadata));
    metadata *newMeta = (metadata *)new;
    
    if (new == NULL)
    {
            num_failed++;
            byte_failed = byte_failed + (int) sz;
            return NULL;
    }
    else if (sz > INT_MAX)
    {
       num_failed++;
       byte_failed = sz;
       return NULL;
    }
    else
    {
        /* store pointer size */
        newMeta->size = sz;
        newMeta->next = NULL;
        
        /* update number of memory allocations */
        num_malloc++;
            
        /* update bytes of memory allocations */ /*Do we include bytes of metadata?*/
        byte_malloc = byte_malloc + (int) sz;
            
        /* update metadata linked list */
        metadata* current = &head;
        
        while (current->next != NULL) {
            current = current->next;
        }
        
        current->next = newMeta;
        newMeta->prev = current;
     
        return (void*) (new + sizeof(metadata)); 
    }
}

void m61_free(void *ptr, const char *file, int line) {
    (void) file, (void) line;   // avoid uninitialized variable warnings
    
    char* new = ptr - sizeof(metadata);
    
    // traverse the linked metadata list looking for memory address
    for (metadata* current = &head; current->next != NULL; current = current->next)
    {
          if (new == current)
          {
          
            /* update bytes of free's */
            byte_freed = byte_freed + (long long) current->size;
            num_freed++;
            
            /* remove in linked list */
             current->prev->next = current->next;
             current->next->prev = current->prev;
             
            free(new);
          }
       }
}

void *m61_realloc(void *ptr, size_t sz, const char *file, int line) {
    void *new_ptr = NULL;
    if (sz)
        new_ptr = m61_malloc(sz, file, line);
   
    if (ptr != NULL && new_ptr != NULL) 
     {
         char* currPointer = ptr - sizeof(metadata);
         metadata* cursor = (metadata *)currPointer;
         size_t old_sz = cursor->size;
         if (old_sz < sz) {
             memcpy(new_ptr, ptr, old_sz);
         }
         else
             memcpy(new_ptr, ptr, sz);
     }
     
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
    
    stats->nactive = num_malloc - num_freed;
    stats->active_size = byte_malloc - byte_freed;
    stats->ntotal = num_malloc;
    stats->total_size = byte_malloc;
    stats->nfail = num_failed;
    stats->fail_size = byte_failed;
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

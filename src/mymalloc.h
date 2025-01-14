#ifndef MYMALLOC_HEADER
#define MYMALLOC_HEADER

#include <stddef.h>
#include <stdio.h>
#include <stdbool.h>
#include <sys/mman.h>

#ifdef ENABLE_LOG
#define LOG(...) fprintf(stderr, "[malloc] " __VA_ARGS__);
#else
#define LOG(...)
#endif

#define N_LISTS 59

#define ADD_BYTES(ptr, n) ((void *) (((char *) (ptr)) + (n)))

typedef struct Chunk {
  size_t size;
  struct Chunk* next;
} Chunk;


/** This is the Block struct, which contains all metadata needed for your 
 *  explicit free list. You are allowed to modify this struct (and will need to 
 *  for certain optimisations) as long as you don't move the definition from 
 *  this file. **/
typedef struct Block Block;

struct Block {
  // Size of the block, including meta-data size.
  size_t size;
  // Is the block allocated or not?
  // The chunk that this block is located
  Chunk* chunk;
  union {
    // when block is allocated, this space gets used for user data
    char data[0];  
    // when block is free, we use these pointers
    struct {
      struct Block* next_free;
      struct Block* prev_free;
    } free_list;
  };
};

// Word alignment
extern const size_t kAlignment;
// Minimum allocation size (1 word)
extern const size_t kMinAllocationSize;
// Size of meta-data per Block
extern const size_t kMetadataSize;
// Maximum allocation size (128 MB)
extern const size_t kMaxAllocationSize;
// Memory size that is mmapped (64 MB)
extern const size_t kMemorySize;

void *my_malloc(size_t size);
void my_free(void *p);

/* Helper functions you are required to implement for internal testing. */

int is_free(Block *block);
size_t block_size(Block *block);

Block *get_start_block(void); 
Block *get_next_block(Block *block);

Block *ptr_to_block(void *ptr);

#endif

#include "mymalloc.h"
#include <stdio.h>
#include <sys/mman.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#define FENCEPOST_MAGIC 0xDEADBEEF
#define RED "\033[31m"
#define GREEN "\033[32m"
#define RESET "\033[0m"

void add_to_free_list(Block* block);
inline static size_t round_up(size_t size, size_t alignment);
Block* split_block(Block* block, size_t size);
Chunk* request_new_chunk(size_t requested_size);
void remove_from_free_list(Block* block);
int is_free(Block *block);
size_t block_size(Block *block);
Block *get_next_block(Block *block);
Block* find_free_block(size_t size);
Block* find_first_block_in_chunk(Chunk* chunk);
bool has_enough_space(size_t size);
void coalesce();

typedef struct Fence_post {
  size_t magic;
} Fence_post;


// Word alignment
const size_t kAlignment = sizeof(size_t);
// Minimum allocation size (1 word)
const size_t kMinAllocationSize = kAlignment;
// Size of meta-data per Block
const size_t kMetadataSize = sizeof(Block);
// Maximum allocation size (128 MB)
const size_t kMaxAllocationSize = (128ull << 20) - kMetadataSize - 2 * sizeof(Fence_post) - sizeof(Chunk);
// Memory size that is mmapped (64 MB)
const size_t kMemorySize = (64ull << 20);


static void *gFirstChunk = NULL;
static void* gLastChunk = NULL;
static Block* free_list_head = NULL;

void debug_dump_state() {
  LOG("--- HEAP STATE ---\n");
  Chunk* c = gFirstChunk;
  while (c) {
    LOG("chunk %p size %zu\n", c, c->size);
    Block* b = find_first_block_in_chunk(c);
    while (b) {
      LOG("  block %p size %zu %s\n", b, b->size, 
             b->allocated ? "alloc" : "free");
      b = get_next_block(b);
    }
    c = c->next;
  }
  LOG("free list: ");
  Block* f = free_list_head;
  while (f) {
    LOG("%p -> ", f);
    f = f->free_list.next_free;
  }
  LOG("NULL\n");
}

void validate_heap() {
  size_t total_size = 0;
  Block* prev = NULL;
  
  for (Chunk* c = gFirstChunk; c; c = c->next) {
    Block* b = find_first_block_in_chunk(c);
    while (b) {
      if ((void*)b >= (void*)c + c->size) {
        LOG("CORRUPTED: block %p outside chunk bounds\n", b);
        abort();
      }
      if (b->chunk != c) {
        LOG("CORRUPTED: block %p wrong chunk ptr\n", b);
        abort();
      }
      total_size += b->size;
      prev = b;
      b = get_next_block(b);
    }
  }
}


void *my_malloc(size_t size) {
  // 1. we want to request a chunk of memory using mmap
  // 2. We then want to put the start of the chunk in a global var
  // So we probably will have to check if there is enough memory in chunk
  // 3. After we get the chunk, we will put the start pointer there (start of our heap)
  // 4. And then we will create the block (how big? I think 64mb)
  // ^^ This only happens on the very first try
  // on the second try, we will implement our 
  if (size == 0) {
    return NULL;
  }

  if (size > kMaxAllocationSize) {
    return NULL;
  }

  // round up the code first
  size = round_up(size, kAlignment);

  // LOG("Block default size: %zu\n", sizeof(Block));

  // The condition should be if !gHeapStart || chunk not enough mem
  // but how do we know if we don't have enough mem? 
  if (!gFirstChunk || !has_enough_space(size)) {
    // should request new chunk
    Chunk* new_chunk = request_new_chunk(size);
    size_t usable_size = new_chunk->size - 2 * sizeof(Fence_post) - sizeof(Chunk);
    Block* block = (Block*)((char*) new_chunk + sizeof(Chunk) + sizeof(Fence_post));
    // LOG("[MAIN] Block address: %p\n", block);
    block->size = usable_size;
    block->allocated = false;
    block->chunk = new_chunk;
    add_to_free_list(block);
    // LOG("[MAIN] Block sizes: %zu\n", usable_size);

    if (!gFirstChunk) {
      gFirstChunk = new_chunk;
      gLastChunk = new_chunk;
    } else {
      ((Chunk*)gLastChunk)->next = new_chunk;
      gLastChunk = new_chunk;
    }
  } 

  
  // find the free block
  Block* free_block = find_free_block(size);

  // if free block full size is bigger than
  // current size (excluding metadata) + this block size + new block size + min allocation size for new block
  if (free_block->size > size + 2 * kMetadataSize + kMinAllocationSize) {
      Block* allocated_block = split_block(free_block, size);
      allocated_block->allocated = true;
      debug_dump_state();
      validate_heap();
      return (void*)((char*) allocated_block + kMetadataSize);
  } else {
    remove_from_free_list(free_block);
    free_block->allocated = true;
    debug_dump_state();
    validate_heap();
    return (void*)((char*) free_block + kMetadataSize);
  }

  return NULL;
}

bool has_enough_space(size_t size) {
  if (find_free_block(size) != NULL) {
    return true;
  }

  return false;
}

Block* split_block(Block* block, size_t size) {
  // Calculate remaining size
  size_t total_size = size + kMetadataSize;
  size_t leftover_size = block_size(block) - total_size;
  // LOG("--------------------------------------------------\n");
  // LOG("[SPLIT_BLOCK] total size: %zu\n", total_size);
  // LOG("[SPLIT_BLOCK] leftover size: %zu\n", leftover_size);

  if (leftover_size < kMetadataSize + kMinAllocationSize) {
    // if too smol, just allocate the whole block
    block->allocated = true;
    remove_from_free_list(block);
    return block;
  }

  Block* new_block = (Block*)((char*) block + leftover_size);
  // LOG("[SPLIT_BLOCK] New block address: %p\n", new_block);

  block->size = leftover_size;
  new_block->size = total_size;
  new_block->allocated = true;
  new_block->chunk = block->chunk;
  // LOG("[SPLIT_BLOCK] New block chunk: %p\n", new_block->chunk);
  return new_block;
}

Chunk* request_new_chunk(size_t requested_size) {

    // total size needed by the chunk
    size_t required_size = requested_size + kMetadataSize + 2 * sizeof(Fence_post) + sizeof(Chunk);
    size_t chunk_size;
    
    if (required_size > kMemorySize) {
        // Need 2 chunks
        chunk_size = 2 * kMemorySize;
    } else {
        chunk_size = kMemorySize;
    }
    
    void* new_chunk = mmap(NULL, chunk_size, PROT_READ | PROT_WRITE,
                          MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
    if (new_chunk == MAP_FAILED) {
        return NULL;
    }

    // Set up chunk header
    Chunk* header = (Chunk*)new_chunk;
    header->size = chunk_size;
    header->next = NULL;  // It's going at the end

    Fence_post* start_fence = (Fence_post*)(header + 1);
    start_fence->magic = FENCEPOST_MAGIC;
    Fence_post* end_fence = (Fence_post*)((char*)header + chunk_size - sizeof(Fence_post));
    end_fence->magic = FENCEPOST_MAGIC;

    // LOG("Chunk size: %zu\n", sizeof(Chunk));
    // LOG("Fence size: %zu\n", sizeof(Fence_post));
    LOG("Header at: %p\n", header);
    LOG("Start fence at: %p\n", start_fence);
    LOG("End fence at: %p\n", end_fence);
    LOG("[REQ_NEW_CHUNK]: First block at: %p\n", (char*)(start_fence + 1));
    LOG("[REQ_NEW_CHUNK] chunk_size: %zu\n", chunk_size);

        // the usable size is kMemorySize - 2 fence post - sizeof(Chunk)
    return new_chunk;
}

void remove_from_free_list(Block* block) {
  if (block->free_list.prev_free) {
    block->free_list.prev_free->free_list.next_free = block->free_list.next_free;
  } else {
    // block is head (because it doesn't have a prev)
    free_list_head = block->free_list.next_free;
  }

  if (block->free_list.next_free) {
    Block* next_block = block->free_list.next_free;
    next_block->free_list.prev_free = block->free_list.prev_free;
  }

  block->free_list.next_free = NULL;
  block->free_list.prev_free = NULL;
}

void my_free(void *ptr) {
  if (!ptr) return;

  // check if ptr is in any of our chunks first
  Chunk* curr_chunk = gFirstChunk;
  while (curr_chunk) {
    if ((void*)ptr >= (void*)curr_chunk && 
        (void*)ptr < (void*)curr_chunk + curr_chunk->size) {
      break;
    }
    curr_chunk = curr_chunk->next;
  }
  
  if (!curr_chunk) return;  // ptr not in any of our chunks
  
  Block* block = ptr_to_block(ptr);
  if (block->chunk != curr_chunk) return;  // metadata corrupted
  
  block->allocated = false;
  add_to_free_list(block);
  coalesce();
  debug_dump_state();
  validate_heap();
}

void coalesce() {
  Block* curr_block = free_list_head;
  
  while (curr_block != NULL) {
    Block* next_block = get_next_block(curr_block);
    
    if (next_block && next_block->chunk == curr_block->chunk && is_free(next_block)) {
      // merge blocks
      curr_block->size += next_block->size;
      remove_from_free_list(next_block);
    } else {
      // move to next block only if we didn't coalesce
      curr_block = curr_block->free_list.next_free;
    }
  }
}

/** These are helper functions you are required to implement for internal testing
 *  purposes. Depending on the optimisations you implement, you will need to
 *  update these functions yourself.
 **/

/* Returns 1 if the given block is free, 0 if not. */
int is_free(Block *block) {
  return !block->allocated;
}

/* Returns the size of the given block */
size_t block_size(Block *block) {
  return block->size;
}

/* Returns the first block in memory (excluding fenceposts) */
Block *get_start_block(void) {
  if (!gFirstChunk) {
    return NULL;
  }
  return find_first_block_in_chunk(gFirstChunk);
}

/* Returns the next block in memory */
Block *get_next_block(Block *block) {
  // Pointer arithmetic time
  // OK so we have a block w/ the sizes in it
  Block* next = (Block*) ((char*) block + block_size(block));
  // LOG("--------------------------------------------------\n");
  // LOG("[GET_NEXT_BLOCK] curr block address: %p\n", block);
  // LOG("[GET_NEXT_BLOCK] curr block size: %zu\n", block_size(block));
  // LOG("[GET_NEXT_BLOCK] next block address: %p\n", next);
  Fence_post* maybe_fence = (Fence_post*)(next);

  void* chunk_end = (char*)block->chunk + block->chunk->size;
  // LOG("[GET_NEXT_BLOCK] next block %p, chunk bound: %p\n", next, chunk_end);
  if ((void*)next >= chunk_end) {
    LOG("[PANIK] next block %p would be outside chunk bounds %p", next, chunk_end);
    return NULL;
  }

  if (maybe_fence->magic == FENCEPOST_MAGIC) {
    // We're in the end of the chunk
    Chunk* current_chunk = block->chunk;
    if (current_chunk->next != NULL) {
      // get the next block in chunk
      return find_first_block_in_chunk(current_chunk->next);
    } else {
      return NULL;
    }
  }

  return next;
}

Block* find_first_block_in_chunk(Chunk* chunk) {
  // pointer arithmetic time
  // we need to add sizeof(Chunk) + sizeof(Fence_post)
  return (Block*)((char*) chunk + sizeof(Chunk) + sizeof(Fence_post));
}

/* Given a ptr assumed to be returned from a previous call to `my_malloc`,
   return a pointer to the start of the metadata block. */
Block *ptr_to_block(void *ptr) {
  return (Block*)((char*)ptr - kMetadataSize);
}

void add_to_free_list(Block* block) {
  /*
  OK so this is all pointer manipulation
  */

 // First we set the new block next to point to the current head
 block->free_list.next_free = free_list_head;
 block->free_list.prev_free = NULL;
 if (free_list_head) {
  // this is a double linked list
  // need to edit the next block as well
  free_list_head->free_list.prev_free = block;
 }

 free_list_head = block;
 block->allocated = false;
}


Block* find_free_block(size_t size) {
  // basic idea: loop through the free list and then find the size
  // that is the smallest but still bigger than the current_size
  Block* best_pointer = NULL;
  Block* curr_pointer = free_list_head;

  while (curr_pointer != NULL) {
    if (curr_pointer->size >= size + kMetadataSize) {
      if (best_pointer == NULL || best_pointer->size > curr_pointer->size) {
        best_pointer = curr_pointer;
      } 
    }

    curr_pointer = curr_pointer->free_list.next_free;
  }
  return best_pointer;
}

inline static size_t round_up(size_t size, size_t alignment) {
  const size_t mask = alignment - 1;
  return (size + mask) & ~mask;
}

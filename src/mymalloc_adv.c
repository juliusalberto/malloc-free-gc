#include "mymalloc.h"
#include <stdio.h>
#include <sys/mman.h>
#include <errno.h>
#include <unistd.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <stddef.h>
#define FENCEPOST_MAGIC 0xDEADBEEF
#define RED "\033[31m"
#define GREEN "\033[32m"
#define RESET "\033[0m"
#define SIZE_MASK (~7UL) 
#define ALLOC_BIT (1UL)
#define GET_FOOTER_SIZE(b) (*(size_t*)((char*)b + block_size(b) - sizeof(size_t)) & SIZE_MASK)
#define LOG_BLOCK(prefix, b) \
    LOG("[%s] Block %p: size=%zu, allocated=%d, next_free=%p, prev_free=%p, footer=%zu\n", \
        prefix, b, block_size(b), !is_free(b), \
        b->free_list.next_free, b->free_list.prev_free, \
        GET_FOOTER_SIZE(b))

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
void coalesce(void);
void debug_dump_state(void);
void validate_heap(void);
void set_allocated(Block *block, bool allocated);
void set_block_size(Block *block, size_t size);
void set_footer(Block *block);
Block *get_prev_block(Block *block);
void coalesce_block(Block* block);
size_t get_list_index(size_t size);


typedef struct Fence_post {
  size_t magic;
} Fence_post;


// Word alignment
const size_t kAlignment = sizeof(size_t);
// Minimum allocation size (1 word)
const size_t kMinAllocationSize = kAlignment;
// Size of meta-data per Block
// Block - data + boundary tag 
const size_t kMetadataSize = offsetof(Block, data);
const size_t kBoundarySize = sizeof(size_t);
// Maximum allocation size (128 MB)
const size_t kMaxAllocationSize = (128ull << 20) - kMetadataSize - kBoundarySize - 2 * sizeof(Fence_post) - sizeof(Chunk);
// Memory size that is mmapped (64 MB)
const size_t kMemorySize = (64ull << 20);



static void *gFirstChunk = NULL;
static void* gLastChunk = NULL;
static Block* free_list_head = NULL;
Block* free_lists[N_LISTS] = {NULL};

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

  // LOG("[MALLOC] malloc for size %zu\n", size);

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
    set_block_size(block, usable_size);
    set_allocated(block, false);
    block->chunk = new_chunk;
    add_to_free_list(block);
    // LOG("[MAIN] Block chunk: %p\n", new_chunk);

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
  if (block_size(free_block) > size + 2 * kMetadataSize + 2 * kBoundarySize + kMinAllocationSize) {
      Block* allocated_block = split_block(free_block, size);
      remove_from_free_list(allocated_block);
      set_allocated(allocated_block, true);
      // debug_dump_state();
      // validate_heap();
      return (void*)((char*) allocated_block + kMetadataSize);
  } else {
    remove_from_free_list(free_block);
    set_allocated(free_block, true);
    // debug_dump_state();
    // validate_heap();
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
  remove_from_free_list(block);
  size_t total_size = size + kMetadataSize + kBoundarySize;
  size_t original_size = block_size(block);
  total_size = (total_size > sizeof(Block) + kBoundarySize) ? total_size : sizeof(Block) + kBoundarySize;
  size_t leftover_size = block_size(block) - total_size;
  if (leftover_size == (size_t) 672) {
    printf("This");
  }

  if (leftover_size < sizeof(Block)) {
    // if too smol, just allocate the whole block
    // LOG("[SPLIT] Too small, return block");
    // LOG("Block next list: %p")
    set_allocated(block, true);
    return block;
  }

  Block* new_block = (Block*)((char*) block + leftover_size);

  set_block_size(block, leftover_size);
  set_block_size(new_block, total_size);
  set_allocated(new_block, true);
  new_block->chunk = block->chunk;
  new_block->free_list.next_free = NULL;
  new_block->free_list.prev_free = NULL;
  // LOG("[SPLIT_BLOCK] New block chunk: %p\n", new_block->chunk);
  // LOG("--------------------------------------------------\n");
  // LOG("[SPLIT] Original block address: %p\n", block);
  // LOG("[SPLIT] Original block chunk: %p\n", block->chunk);
  // LOG("[SPLIT] Original block size: %zu\n", original_size);
  // LOG("[SPLIT] Total size for new block: %zu\n", total_size);
  // LOG("[SPLIT] Leftover size: %zu\n", leftover_size);
  // LOG("[SPLIT] End of chunk boundary: %p\n", (char*)block->chunk + block->chunk->size);
  // if ((new_block > (char*)block->chunk + block->chunk->size)) {
  //   LOG("[SPLIT PANIK] SPLITTED BLOCK LOCATED AHEAD OF CHUNK\n");
  // }

  // LOG_BLOCK("[SPLIT] OLD BLOCK AFTER SPLIT", block);
  // LOG_BLOCK("[SPLIT] NEW BLOCK AFTER SPLIT", new_block);
  // LOG("--------------------------------------------------\n");
  

  return new_block;
}

Chunk* request_new_chunk(size_t requested_size) {

    // total size needed by the chunk
    size_t required_size = requested_size + kMetadataSize + kBoundarySize + 2 * sizeof(Fence_post) + sizeof(Chunk);
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
    // LOG("Header at: %p\n", header);
    // LOG("Start fence at: %p\n", start_fence);
    // LOG("End fence at: %p\n", end_fence);
    // LOG("[REQ_NEW_CHUNK]: First block at: %p\n", (char*)(start_fence + 1));
    // LOG("[REQ_NEW_CHUNK] chunk_size: %zu\n", chunk_size);

        // the usable size is kMemorySize - 2 fence post - sizeof(Chunk)
    return new_chunk;
}

void remove_from_free_list(Block* block) {
  size_t index = get_list_index(block_size(block));

  // LOG_BLOCK("[REMOVE FROM FREE LIST] before removing", block);
  if (block->free_list.prev_free) {
    // LOG_BLOCK("[REMOVE FROM FREE LIST] before removing - prev block", block->free_list.prev_free);
    block->free_list.prev_free->free_list.next_free = block->free_list.next_free;
    // LOG_BLOCK("[REMOVE FROM FREE LIST] after removing - prev block", block->free_list.prev_free);
  } else if (free_lists[index] == block) {
    // add to list
    free_lists[index] = block->free_list.next_free;
  }

  if (block->free_list.next_free) {
    Block* next_block = block->free_list.next_free;
    // LOG_BLOCK("[REMOVE FROM FREE LIST] before removing - next block", next_block);
    next_block->free_list.prev_free = block->free_list.prev_free;
    // LOG_BLOCK("[REMOVE FROM FREE LIST] after removing - next block", next_block);
  }

  block->free_list.next_free = NULL;
  block->free_list.prev_free = NULL;
  // validate_heap();
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

  // LOG("[FREE] free for block %p with size %zu\n", block, block_size(block));

  if (block->chunk != curr_chunk) return;  // metadata corrupted
  
  set_allocated(block, false);
  // LOG_BLOCK("[MYFREE] BEFORE COALESCE", block);
  coalesce_block(block);
  // debug_dump_state();
  // validate_heap();
}

void coalesce() {
  Block* curr_block = free_list_head;
  
  while (curr_block != NULL) {
    Block* next_block = get_next_block(curr_block);
    
    if (next_block && next_block->chunk == curr_block->chunk && is_free(next_block)) {
      // merge blocks
      size_t curr_block_size = block_size(curr_block);
      size_t next_block_size = block_size(next_block);
      set_block_size(curr_block, curr_block_size + next_block_size);
      remove_from_free_list(next_block);
    } else {
      // move to next block only if we didn't coalesce
      curr_block = curr_block->free_list.next_free;
    }
  }
}

void coalesce_block(Block* block) {
  Block *prev = get_prev_block(block);

  // coalesce with prev if free
  if (prev && prev->chunk == block->chunk && is_free(prev)) {
    // merge blocks
    remove_from_free_list(prev);
    size_t prev_size = block_size(prev);
    size_t curr_size = block_size(block);
    set_block_size(prev, prev_size + curr_size);
    block = prev;  // Update our reference to the merged block
  }

  Block *next = get_next_block(block);
  if (next && next->chunk == block->chunk && is_free(next)) {
    remove_from_free_list(next);
    set_block_size(block, block_size(next) + block_size(block));
  }

  if (block > ((char*) block->chunk + block->chunk->size)) {
    LOG("[COALESCE] something wrong with the block positioning - above chunk")
  }

  add_to_free_list(block);
  // validate_heap();
}

/** These are helper functions you are required to implement for internal testing
 *  purposes. Depending on the optimisations you implement, you will need to
 *  update these functions yourself.
 **/

/* Returns 1 if the given block is free, 0 if not. */
int is_free(Block *block) {
  // return the last bit in size
  // if bit is 1 -> means it is allocated
  // therefore it is not free
  return !(block->size & ALLOC_BIT);
}

/* Returns the size of the given block */
size_t block_size(Block *block) {
  return block->size & SIZE_MASK;
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
  Fence_post* maybe_fence = (Fence_post*)(next);

  void* chunk_end = (char*)block->chunk + block->chunk->size;
  // LOG("[GET_NEXT_BLOCK] next block %p, chunk bound: %p\n", next, chunk_end);
  // LOG("--------------------------------------------------\n");
  if ((void*)next >= chunk_end) {
    // LOG("[PANIK] next block %p would be outside chunk bounds %p\n", next, chunk_end);
    return NULL;
  }

  if (maybe_fence->magic == FENCEPOST_MAGIC) {
    // We're in the end of the chunk
    // LOG("[GET_NEXT_BLOCK] AT THE END OF CHUNK\n");
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

 size_t index = get_list_index(block_size(block));
 block->free_list.next_free = free_lists[index];
 block->free_list.prev_free = NULL;

 if (free_lists[index]) {
  free_lists[index]->free_list.prev_free = block;
 }

 free_lists[index] = block;

 // First we set the new block next to point to the current head
 set_allocated(block, false);
//  LOG_BLOCK("[ADD_TO_FREE_LIST] after adding free list", block);
}


Block* find_free_block(size_t size) {
  size_t index = get_list_index(size);
  size_t start_index = index + 1;
  if (start_index >= N_LISTS) {
    // if the original index was already the largest list,
    // we can't add 1. So just make start_index the last list.
    start_index = N_LISTS - 1;
  }

  // 1) Search from `start_index` up to the second-to-last list 
  //    using a first-fit approach
  for (size_t i = start_index; i < N_LISTS - 1; i++) {
    for (Block* curr = free_lists[i]; curr; curr = curr->free_list.next_free) {
      if (block_size(curr) >= size) {
        // First block big enough => return immediately (first-fit)
        return curr;
      }
    }
  }

  // 2) If we got here, we haven't found anything in those lists;
  //    now we do a "best fit" in the last list
  Block* best = NULL;
  for (Block* curr = free_lists[N_LISTS - 1]; curr; curr = curr->free_list.next_free) {
    size_t csize = block_size(curr);
    if (csize >= size) {
      if (!best || csize < block_size(best)) {
          best = curr; // track the smallest >= size
      }
    }
  }

  return best;  // might be NULL if nothing is big enough
}

inline static size_t round_up(size_t size, size_t alignment) {
  const size_t mask = alignment - 1;
  return (size + mask) & ~mask;
}

void debug_dump_state() {
  LOG("--- HEAP STATE ---\n");
  Chunk* c = gFirstChunk;
  while (c) {
    LOG("chunk %p size %zu\n", c, c->size);
    Block* b = find_first_block_in_chunk(c);
    while (b && b->chunk == c) {
      LOG("  block %p size %zu %s\n", b, block_size(b), 
             !is_free(b) ? "alloc" : "free");
      b = get_next_block(b);
    }
    c = c->next;
  }
  LOG("Free lists:\n");
  int j;
  for(size_t i = 0; i < N_LISTS; i++) {
    LOG("List %zu, size: %zu ", i, i * 8);
    Block* f = free_lists[i];
    j = 0;
    while (f && j < 50) {
        LOG("%p (size: %zu) -> ", f, f->size);
        f = f->free_list.next_free;
        j++;
    }
    LOG("NULL\n");
  }
}

void validate_heap() {
  size_t total_size = 0;
  Block* prev = NULL;
  
  for (Chunk* c = gFirstChunk; c; c = c->next) {
    Block* b = find_first_block_in_chunk(c);
    while (b && b->chunk == c) {
      if ((void*)b >= (void*)c + c->size) {
        LOG("VALIDATE: current chunk: %p, current chunk bound: %p\n", c, (void*)c + c->size);
        LOG("CORRUPTED: block %p outside chunk bounds\n", b);
        abort();
      }
      if (b->chunk != c) {
        LOG("CORRUPTED: block %p wrong chunk ptr\n", b);
        abort();
      }

      size_t header = b->size;             // includes ALLOC_BIT
      size_t footer = *(size_t*)((char*)b + (header & SIZE_MASK) - sizeof(size_t));

      if ((header & SIZE_MASK) != (footer & SIZE_MASK)) {
        LOG("CORRUPTION: block %p header size=%zu footer size=%zu\n",
              b, header & SIZE_MASK, footer & SIZE_MASK);
        abort();
      }

      total_size += block_size(b);
      prev = b;
      b = get_next_block(b);
    }
  }
}

void set_allocated(Block *block, bool allocated) {
  if (allocated) {
    // we want to set the last bit to 1
    block->size = block->size |= ALLOC_BIT;
  } else {
    // we want to set the last bit to 0
    block->size &= ~ALLOC_BIT;
  }
}

void set_block_size(Block *block, size_t size) {
  bool was_allocated = !is_free(block);
  size_t aligned_size = round_up(size, 8);
  block->size = (aligned_size & SIZE_MASK);

  if (was_allocated) {
    block->size |= ALLOC_BIT;
  }

  set_footer(block);
}

void set_footer(Block* block) {
  // we want to set the footer at the very end
  // we use size_t as the footer - why? because we store
  // the size and allocated also using size_t in the header
  size_t* footer_loc = (size_t*)((char*) block + block_size(block) - sizeof(size_t));
  // now we copy the header
  *footer_loc = block->size;
}

Block* get_prev_block(Block* block) {
  // check block - 1, it's either a fencepost or a boundary tag
  size_t* prev_footer = (size_t*)((char*) block - sizeof(size_t));
  size_t prev_size = (*prev_footer & SIZE_MASK);
  Fence_post* maybe_fence = (Fence_post*)((char*) block - sizeof(Fence_post));

  if (maybe_fence->magic == FENCEPOST_MAGIC) {
    return NULL; // reach the fence
  }

  return (Block*)((char*) block - prev_size);
}

size_t get_list_index(size_t size) {
  size_t index = (size / 8) - 1;
  return index >= N_LISTS ? N_LISTS - 1 : index;
}
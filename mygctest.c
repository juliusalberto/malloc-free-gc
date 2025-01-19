#include "src/mygc.h"
#include <string.h>
#include <assert.h>

// Helper function to count currently allocated blocks
size_t count_allocated_blocks() {
  size_t count = 0;
  Block *block = get_start_block();
  
  while (block) {
    if (!is_free(block)) {
        count++;
    }
    block = get_next_block(block);
  }
  return count;
}

void *my_calloc_gc(size_t size) {
  void *p = my_malloc(size);
  memset(p, 0, size);
  return p;
}

int main(void) {
  set_start_of_stack(__builtin_frame_address(0));

  // Test 1: Basic garbage collection test
  char *a = my_calloc_gc(8);
  char *b = my_calloc_gc(16);
  
  size_t blocks_before = count_allocated_blocks();
  printf("Allocated blocks before GC: %zu\n", blocks_before);
  
  b = NULL;
  
  // Run garbage collection
  my_gc();
  
  // Count blocks after GC
  size_t blocks_after = count_allocated_blocks();
  printf("Allocated blocks after GC: %zu\n", blocks_after);
  assert(blocks_after == blocks_before - 1);
  
  // Test 2: Verify that a is still accessible
  a[0] = 'X'; 
  
  printf("GC test passed successfully!\n");
  return 0;
}
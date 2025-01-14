#include "internal-tests.h"
#include <stdlib.h> /* Defines rand, srand */
#include <time.h>   /* Defines time */

/** Starting code for writing tests that measure memory fragmentation.
 *  Note that the CI will not run this test intentionally. 
 */

// You can modify these values to be larger or smaller as needed
// By default they are quite small to help you test your code.
#define REPTS 1000
#define NUM_PTRS 100
#define MAX_ALLOC_SIZE 4096

char *ptrs[NUM_PTRS];

size_t peak_allocated = 0;
size_t peak_payload = 0;
size_t curr_allocated = 0;
size_t curr_payload = 0;

static void update_stats(void) {
  curr_allocated = 0;
  curr_payload = 0;
  for (Block* b = get_start_block(); b; b = get_next_block(b)) {
    if (!is_free(b)) {
      curr_allocated += b->size;
      curr_payload += b->size - kMetadataSize;
    }
  }
  peak_allocated = (curr_allocated > peak_allocated) ? curr_allocated : peak_allocated;
  peak_payload = (curr_payload > peak_payload) ? curr_payload : peak_payload;
}

/* Returns a random number between min and max (inclusive) */
int random_in_range(int min, int max) {
  return min + rand() / (RAND_MAX / (max - min + 1) + 1);
}

/* Performs REPTS number of calls to my_malloc/my_free. */
void random_allocations() {
  for (int i = 0; i < REPTS; i++) {
    int idx = random_in_range(0, NUM_PTRS-1);
    if (ptrs[idx] == NULL) {
      size_t random_size = (size_t) random_in_range(0, MAX_ALLOC_SIZE);
      ptrs[idx] = my_malloc(random_size);
      update_stats();
    } else {
      my_free(ptrs[idx]);
      ptrs[idx] = NULL;
    }
  }
}

/* Usage: passing an unsigned integer as the first argument will use that value
 * to seed the pRNG. This will allow you to re-run the same sequence of calls to
 * my_malloc and my_free for the purposes of debugging or measuring 
 * fragmentation. 
 * If a seed is not given to the program it will use the current time instead.
 */
int main(int argc, char const *argv[]) {
  unsigned int seed; 
  if (argc < 2) {
    seed = (unsigned int) time(NULL); 
  } else {
    sscanf(argv[1], "%u", &seed); 
  }
  fprintf(stderr, "Running fragmentation test with random seed: %u\n", seed);
  srand(seed);
  random_allocations(); 

  double peak_util = ((double)peak_payload / peak_allocated) * 100;
  printf("peak stats:\n");
  printf("  allocated: %zu bytes\n", peak_allocated);
  printf("  payload:   %zu bytes\n", peak_payload);
  printf("  util:      %.2f%%\n", peak_util);
  printf("  waste:     %.2f%%\n", 100.0 - peak_util);

  /* TODO: put your code to measure and report memory fragmentation here */

  return 0;
}
# Memory Allocator with Garbage Collector

An implementation of a memory allocator and garbage collector in C, featuring explicit free lists with optimizations for better memory management and automated garbage collection.

## Features

- Explicit free list implementation
- Best-fit placement strategy
- Memory coalescing
- Boundary tag optimization
- Multiple free lists
- Conservative mark-and-sweep garbage collection

## Building and Testing

Build all files:
```bash
make
```

## Memory Allocator Usage

```c
#include "mymalloc.h"

int main() {
    // Allocate memory
    void* ptr = my_malloc(size);
    
    // Free memory
    my_free(ptr);
    
    return 0;
}
```

## Garbage Collector Usage

```c
#include "mygc.h"

void* my_calloc_gc(size_t size) {
    void* p = my_malloc(size);
    memset(p, 0, size);
    return p;
}

int main() {
    set_start_of_stack(__builtin_frame_address(0));
    
    // Allocate memory
    char* ptr = my_calloc_gc(8);
    
    // Run garbage collection
    my_gc();
    
    return 0;
}
```

## Implementation Details

- Uses explicit free lists for efficient memory management
- Best-fit placement policy to minimize fragmentation
- Boundary tags for O(1) coalescing
- Multiple free lists optimization for faster allocation
- Conservative garbage collection with stack scanning

#ifndef TRACEALLOC_H
#define TRACEALLOC_H
#include <cstdlib>
#include <string>

class tracealloc {
private:
    size_t portable_ish_malloced_size(const void* p);
    size_t allocated_sz = 0;
public:
     size_t getAllocSz();
     void* tmalloc(size_t size);

     void* tcalloc(size_t _Count, size_t _Size);

     void* trealloc(void* block, size_t size);

     void tfree(const void* block);
};


#define malloc(size) t.tmalloc(size)
#define calloc(count, size) t.tcalloc(count, size)
#define realloc(block, size) t.trealloc(block, size)
#define free(block) t.tfree(block)
extern tracealloc t;
#endif
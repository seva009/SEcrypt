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

tracealloc t;

#if defined(__linux__)
#include <malloc.h>
    size_t tracealloc::portable_ish_malloced_size(const void* p) {
        return malloc_usable_size((void*)p);
    }
#elif defined(__APPLE__)
#include <malloc/malloc.h>
    size_t tracealloc::portable_ish_malloced_size(const void* p) {
        return malloc_size(p);
    }
#elif defined(_WIN32)
#include <malloc.h>
    size_t tracealloc::portable_ish_malloced_size(const void* p) {
        return _msize((void*)p);
    }
#else
#error "oops, I don't know this system"
#endif

    size_t tracealloc::getAllocSz() {
        return allocated_sz;
    }
    void* tracealloc::tmalloc(size_t size) {
        allocated_sz += size;
        return malloc(size);
    }

     void* tracealloc::tcalloc(size_t _Count, size_t _Size) {
        allocated_sz += _Count * _Size;
        return calloc(_Count, _Size);
    }

     void* tracealloc::trealloc(void* block, size_t size) {
        allocated_sz += size;
        return realloc(block, size);
    }

     void tracealloc::tfree(const void* block) {
        allocated_sz -= portable_ish_malloced_size(block);
        free((void*)block);
    }

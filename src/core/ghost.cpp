#ifndef GHOST_H
#define GHOST_H

#include <vector>
#include <cstdint>
#include <sys/mman.h>
#include <unistd.h>
#include <cstring>

namespace ENI {
    class Ghost {
    public:
        void execute_in_memory(const std::vector<uint8_t>& payload) {
            size_t size = payload.size();
            void* mem = mmap(NULL, size, PROT_NONE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);
            if (mem == MAP_FAILED) return;

            mprotect(mem, size, PROT_WRITE);
            std::memcpy(mem, payload.data(), size);
            mprotect(mem, size, PROT_READ | PROT_EXEC);

            // ((void(*)())mem)();

            mprotect(mem, size, PROT_NONE);
            munmap(mem, size);
        }
    };
}

#endif

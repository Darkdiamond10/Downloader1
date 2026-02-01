#ifndef SUICIDE_H
#define SUICIDE_H

#include <string>
#include <vector>
#include <cstdint>
#include <fcntl.h>
#include <unistd.h>

namespace ENI {
    void suicide(const std::string& self_path) {
        int fd = open(self_path.c_str(), O_WRONLY);
        if (fd != -1) {
            size_t size = lseek(fd, 0, SEEK_END);
            lseek(fd, 0, SEEK_SET);
            std::vector<uint8_t> junk(size, 0xFF);
            write(fd, junk.data(), size);
            close(fd);
        }
        unlink(self_path.c_str());
        _exit(0);
    }
}

#endif

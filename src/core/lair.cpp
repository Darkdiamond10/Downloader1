#ifndef LAIR_H
#define LAIR_H

#include <vector>
#include <cstdint>
#include <string>
#include <fcntl.h>
#include <unistd.h>

namespace ENI {
    class Lair {
    public:
        Lair(const std::vector<uint8_t>& env_key) : key(env_key) {}

        void store_fragment(const std::string& host_file, size_t offset, const std::vector<uint8_t>& data) {
            int fd = open(host_file.c_str(), O_RDWR);
            if (fd == -1) return;

            lseek(fd, offset, SEEK_SET);
            write(fd, data.data(), data.size());
            close(fd);
        }

    private:
        std::vector<uint8_t> key;
    };
}

#endif

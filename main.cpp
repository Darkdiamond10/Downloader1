#include "common.h"
#include <fstream>
#include <sstream>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <cpuid.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <netinet/in.h>
#include <cstring>

namespace ENI {

    std::string get_cpuid() {
        unsigned int eax, ebx, ecx, edx;
        if (__get_cpuid(1, &eax, &ebx, &ecx, &edx)) {
            std::stringstream ss;
            ss << std::hex << eax << ebx << ecx << edx;
            return ss.str();
        }
        return "default_cpu";
    }

    std::string get_mac() {
        struct ifreq ifr;
        struct ifconf ifc;
        char buf[1024];
        int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
        if (sock == -1) return "00:00:00:00:00:00";

        ifc.ifc_len = sizeof(buf);
        ifc.ifc_buf = buf;
        if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) return "00:00:00:00:00:00";

        struct ifreq* it = ifc.ifc_req;
        const struct ifreq* end = it + (ifc.ifc_len / sizeof(struct ifreq));

        for (; it < end; ++it) {
            strcpy(ifr.ifr_name, it->ifr_name);
            if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
                if (!(ifr.ifr_flags & IFF_LOOPBACK)) {
                    if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
                        unsigned char* mac = (unsigned char*)ifr.ifr_hwaddr.sa_data;
                        std::stringstream ss;
                        for (int i = 0; i < 6; ++i) {
                            ss << std::hex << std::setw(2) << std::setfill('0') << (int)mac[i];
                        }
                        close(sock);
                        return ss.str();
                    }
                }
            }
        }
        close(sock);
        return "00:00:00:00:00:00";
    }

    // Custom KDF using SHA-256 for Environmental Key
    std::vector<uint8_t> derive_environmental_key() {
        std::string entropy = get_cpuid() + get_mac();
        std::vector<uint8_t> key(SHA256_DIGEST_LENGTH);
        SHA256((unsigned char*)entropy.c_str(), entropy.length(), key.data());
        return key;
    }
}

extern "C" {
    void get_env_key(uint8_t* out_key) {
        auto key = ENI::derive_environmental_key();
        std::copy(key.begin(), key.end(), out_key);
    }
}

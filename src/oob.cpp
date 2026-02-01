#include <netdb.h>
#include <arpa/inet.h>
#include <iostream>

namespace ENI {
    bool check_oob_trigger(const std::string& domain) {
        struct hostent *he = gethostbyname(domain.c_str());
        if (he == NULL) return false;

        // If domain resolves to a specific trigger IP (e.g. 127.0.0.9), trigger suicide
        struct in_addr **addr_list = (struct in_addr **)he->h_addr_list;
        for(int i = 0; addr_list[i] != NULL; i++) {
            if (std::string(inet_ntoa(*addr_list[i])) == "127.0.0.9") {
                return true;
            }
        }
        return false;
    }
}

#include <vector>
#include <random>
#include <cstdint>

namespace ENI {

    // Switching to Additive Secret Sharing for simplicity and robustness in C++
    // Key = Share1 ^ Share2 ^ ... ^ ShareN
    std::vector<std::vector<uint8_t>> split_key_additive(const std::vector<uint8_t>& key, int n) {
        std::vector<std::vector<uint8_t>> shares(n, std::vector<uint8_t>(key.size()));
        std::random_device rd;
        std::mt19937 gen(rd());
        std::uniform_int_distribution<> dis(0, 255);

        for (size_t i = 0; i < key.size(); ++i) {
            uint8_t current_xor = 0;
            for (int j = 0; j < n - 1; ++j) {
                shares[j][i] = dis(gen);
                current_xor ^= shares[j][i];
            }
            shares[n - 1][i] = key[i] ^ current_xor;
        }
        return shares;
    }

    std::vector<uint8_t> reconstruct_key(const std::vector<std::vector<uint8_t>>& shares) {
        if (shares.empty()) return {};
        std::vector<uint8_t> key(shares[0].size(), 0);
        for (const auto& share : shares) {
            for (size_t i = 0; i < key.size(); ++i) {
                key[i] ^= share[i];
            }
        }
        return key;
    }
}

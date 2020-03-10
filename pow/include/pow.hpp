#include <chrono>
#include <iostream>
#include <vector>

struct pow_difficulty_t {
    std::chrono::milliseconds timestamp;
    int difficulty;
};

int get_valid_difficulty(const std::string& timestamp,
                         const std::vector<pow_difficulty_t>& history);

bool checkPoW(const std::string& nonce, const std::string& timestamp,
              const std::string& ttl, const std::string& recipient,
              const std::string& data, std::string& messageHash,
              const int difficulty);

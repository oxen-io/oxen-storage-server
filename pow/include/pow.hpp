#include <iostream>
#include <vector>
#include <chrono>

struct pow_difficulty_t {
  std::chrono::milliseconds timestamp;
  int difficulty;
};

bool checkPoW(const std::string& nonce, const std::string& timestamp,
              const std::string& ttl, const std::string& recipient,
              const std::string& data, std::string& messageHash,
              const std::vector<pow_difficulty_t>& difficulty_history);

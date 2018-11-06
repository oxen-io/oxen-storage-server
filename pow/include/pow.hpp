#include <iostream>
#include <vector>

bool checkPoW(const std::string& nonce, const std::string& timestamp,
              const std::string& ttl, const std::string& recipient,
              const std::vector<uint8_t>& data, std::string& messageHash);

#pragma once

#include <stdint.h>
#include <string>
#include <vector>

namespace service_node {
namespace storage {

struct Item {
    Item(const std::string& hash, const std::string& pubKey, uint64_t timestamp,
         uint64_t expirationTimestamp, const uint8_t* bytes, size_t dataSize)
        : hash(hash), pubKey(pubKey), bytes(bytes, bytes + dataSize),
          timestamp(timestamp), expirationTimestamp(expirationTimestamp) {}
    std::string hash;
    std::string pubKey;
    std::vector<uint8_t> bytes;
    uint64_t timestamp;
    uint64_t expirationTimestamp;
};

} // namespace storage

} // namespace service_node

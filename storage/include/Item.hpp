#pragma once

#include <stdint.h>
#include <string>

namespace service_node {
namespace storage {

struct Item {
    Item(const std::string& hash, const std::string& pubKey, uint64_t timestamp,
         uint64_t expirationTimestamp, const std::string& bytes)
        : hash(hash), pubKey(pubKey), bytes(bytes), timestamp(timestamp),
          expirationTimestamp(expirationTimestamp) {}
    std::string hash;
    std::string pubKey;
    std::string bytes;
    uint64_t timestamp;
    uint64_t expirationTimestamp;
};

} // namespace storage

} // namespace service_node

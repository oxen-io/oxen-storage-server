#pragma once

#include <stdint.h>
#include <string>

namespace service_node {
namespace storage {

struct Item {
    Item(const std::string& hash, const std::string& pubKey, uint64_t timestamp,
         uint64_t ttl, uint64_t expirationTimestamp, const std::string& nonce,
         const std::string& bytes)
        : hash(hash), pubKey(pubKey), timestamp(timestamp), ttl(ttl),
          expirationTimestamp(expirationTimestamp), nonce(nonce), bytes(bytes) {
    }
    std::string hash;
    std::string pubKey;
    uint64_t timestamp;
    uint64_t ttl;
    uint64_t expirationTimestamp;
    std::string nonce;
    std::string bytes;
};

} // namespace storage

} // namespace service_node

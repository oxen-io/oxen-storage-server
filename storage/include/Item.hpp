#pragma once

#include <stdint.h>
#include <string>

namespace service_node {
namespace storage {

struct Item {
    Item(const std::string& hash, const std::string& pubKey, uint64_t timestamp,
         uint64_t ttl, uint64_t expirationTimestamp, const std::string& nonce,
         const std::string& bytes)
        : hash(hash), pub_key(pubKey), timestamp(timestamp), ttl(ttl),
          expiration_timestamp(expirationTimestamp), nonce(nonce), data(bytes) {
    }
    Item() = default;
    std::string hash;
    std::string pub_key;
    uint64_t timestamp;
    uint64_t ttl;
    uint64_t expiration_timestamp;
    std::string nonce;
    std::string data;
};

} // namespace storage

} // namespace service_node

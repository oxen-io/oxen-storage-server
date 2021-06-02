#pragma once

#include <chrono>
#include <string>
#include "oxen_common.h"

namespace oxen::storage {

struct Item {
    std::string hash;
    std::string pub_key;
    std::chrono::system_clock::time_point timestamp;
    std::chrono::system_clock::time_point expiration;
    std::string data;

    Item() = default;
    Item(
            std::string hash,
            std::string pub_key,
            std::chrono::system_clock::time_point timestamp,
            std::chrono::system_clock::time_point expiration,
            std::string data) :
        hash{std::move(hash)},
        pub_key{std::move(pub_key)},
        timestamp{std::move(timestamp)},
        expiration{std::move(expiration)},
        data{std::move(data)}
    {}

    // Explicit conversion from a message_t
    explicit Item(message_t&& msg) :
        hash{std::move(msg.hash)}, pub_key{std::move(msg.pub_key)}, timestamp{std::move(msg.timestamp)},
        expiration{std::move(msg.expiry)}, data{std::move(msg.data)}
    {}
    explicit Item(const message_t& msg) :
        hash{msg.hash}, pub_key{msg.pub_key}, timestamp{msg.timestamp}, expiration{msg.expiry}, data{msg.data}
    {}

    // Explicit conversion to a message_t
    explicit operator message_t() const & {
        return {pub_key, data, hash, timestamp, expiration};
    }
    explicit operator message_t() && {
        return {std::move(pub_key), std::move(data), std::move(hash), std::move(timestamp),
            std::move(expiration)};
    }
};

} // namespace oxen::storage

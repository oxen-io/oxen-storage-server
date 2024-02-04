#pragma once

#include "namespace.h"
#include "pubkey.h"

#include <chrono>

namespace oxenss {

/// message received from a client
struct message {
    user_pubkey pubkey;
    std::string hash;
    namespace_id msg_namespace;
    std::chrono::system_clock::time_point timestamp;
    std::chrono::system_clock::time_point expiry;
    std::string data;

    message() = default;

    message(user_pubkey pubkey,
            std::string hash,
            namespace_id msg_ns,
            std::chrono::system_clock::time_point timestamp,
            std::chrono::system_clock::time_point expiry,
            std::string data) :
            pubkey{std::move(pubkey)},
            hash{std::move(hash)},
            msg_namespace{msg_ns},
            timestamp{timestamp},
            expiry{expiry},
            data{std::move(data)} {}

    message(std::string hash,
            namespace_id msg_ns,
            std::chrono::system_clock::time_point timestamp,
            std::chrono::system_clock::time_point expiry,
            std::string data) :
            hash{std::move(hash)},
            msg_namespace{msg_ns},
            timestamp{timestamp},
            expiry{expiry},
            data{std::move(data)} {}
};

}  // namespace oxenss

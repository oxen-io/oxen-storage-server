#pragma once

#include <cstdint>
#include <string>
#include <vector>
#include <ostream>

struct sn_record_t {
    uint16_t port;
    std::string address; // Snode address
    std::string ip;      // Snode ip
};

namespace loki {

/// message as received by client
struct message_t {

    std::string pub_key;
    std::string data;
    std::string hash;
    uint64_t ttl;
    uint64_t timestamp;
    std::string nonce;

    message_t(const std::string& pk, const std::string& text,
              const std::string& hash, uint64_t ttl, uint64_t timestamp,
              const std::string& nonce)
        : pub_key(pk), data(text), hash(hash), ttl(ttl), timestamp(timestamp),
          nonce(nonce) {}
};

} // namespace loki

namespace std {

template <>
struct hash<sn_record_t> {
    std::size_t operator()(const sn_record_t& k) const {
#ifdef INTEGRATION_TEST
        return hash<uint16_t>{}(k.port);
#else
        return hash<std::string>{}(k.address);
#endif
    }
};

} // namespace std

inline bool operator<(const sn_record_t& lhs, const sn_record_t& rhs) {
#ifdef INTEGRATION_TEST
    return lhs.port < rhs.port;
#else
    return lhs.address < rhs.address;
#endif
}

static std::ostream& operator<<(std::ostream& os, const sn_record_t& sn) {
#ifdef INTEGRATION_TEST
    return os << sn.port;
#else
    return os << sn.address;
#endif
}

static bool operator==(const sn_record_t& lhs, const sn_record_t& rhs) {
#ifdef INTEGRATION_TEST
    return lhs.port == rhs.port;
#else
    return lhs.address == rhs.address;
#endif
}

static bool operator!=(const sn_record_t& lhs, const sn_record_t& rhs) {
    return !operator==(lhs, rhs);
}

using swarm_id_t = uint64_t;

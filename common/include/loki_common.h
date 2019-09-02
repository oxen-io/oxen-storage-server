#pragma once

#include "spdlog/fmt/ostr.h" // for operator<< overload

#include <cstdint>
#include <ostream>
#include <string>
#include <vector>

#include <boost/optional.hpp>

// TODO: this should be a proper struct w/o heap allocation!
using sn_pub_key_t = std::string;

struct sn_record_t {

    // our 32 byte pub keys should always be 52 bytes long in base32z
    static constexpr size_t BASE_LEN = 52;

  private:
    uint16_t port_;
    std::string sn_address_; // Snode address (pubkey plus .snode)
    std::string pub_key_;    // base32z
    std::string pub_key_hex_;
    std::string ip_; // Snode ip
  public:
    sn_record_t(uint16_t port, const std::string& address,
                const std::string& pk_hex, const std::string& ip)
        : port_(port), pub_key_hex_(pk_hex), ip_(ip) {
        set_address(address);
    }

    sn_record_t() = default;

    void set_ip(const std::string& ip) { ip_ = ip; }
    void set_port(uint16_t port) { port_ = port; }

    /// Set service node's public key in base32z (without .snode part)
    void set_address(const std::string& addr) {

        if (addr.size() != BASE_LEN)
            throw std::runtime_error("snode public key has incorrect size");

        sn_address_ = addr;
        sn_address_.append(".snode");
        pub_key_ = addr;
    }

    uint16_t port() const { return port_; }
    const std::string& sn_address() const { return sn_address_; }
    const std::string& pub_key() const { return pub_key_; }
    const std::string& pub_key_hex() const { return pub_key_hex_; }
    const std::string& ip() const { return ip_; }

    template <typename OStream>
    friend OStream& operator<<(OStream& os, const sn_record_t& record) {
#ifdef INTEGRATION_TEST
        os << record.port();
#else
        os << record.sn_address();
#endif
    }
};

constexpr size_t USER_PUBKEY_SIZE = 66;

class user_pubkey_t {

    std::string pubkey_;

    user_pubkey_t() {}

    user_pubkey_t(std::string&& pk) : pubkey_(std::move(pk)) {}

    user_pubkey_t(const std::string& pk) : pubkey_(pk) {}

  public:
    static user_pubkey_t create(std::string&& pk, bool& success) {
        success = true;
        if (pk.size() != USER_PUBKEY_SIZE) {
            success = false;
            return {};
        }
        return user_pubkey_t(std::move(pk));
    }

    static user_pubkey_t create(const std::string& pk, bool& success) {
        success = true;
        if (pk.size() != USER_PUBKEY_SIZE) {
            success = false;
            return {};
        }
        return user_pubkey_t(pk);
    }

    const std::string& str() const { return pubkey_; }
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
        return hash<uint16_t>{}(k.port());
#else
        return hash<std::string>{}(k.sn_address());
#endif
    }
};

} // namespace std

inline bool operator<(const sn_record_t& lhs, const sn_record_t& rhs) {
#ifdef INTEGRATION_TEST
    return lhs.port() < rhs.port();
#else
    return lhs.sn_address() < rhs.sn_address();
#endif
}

static std::ostream& operator<<(std::ostream& os, const sn_record_t& sn) {
#ifdef INTEGRATION_TEST
    return os << sn.port();
#else
    return os << sn.sn_address();
#endif
}

static bool operator==(const sn_record_t& lhs, const sn_record_t& rhs) {
#ifdef INTEGRATION_TEST
    return lhs.port() == rhs.port();
#else
    return lhs.sn_address() == rhs.sn_address();
#endif
}

static bool operator!=(const sn_record_t& lhs, const sn_record_t& rhs) {
    return !operator==(lhs, rhs);
}

using swarm_id_t = uint64_t;

constexpr swarm_id_t INVALID_SWARM_ID = UINT64_MAX;

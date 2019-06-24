#pragma once

#include <cstdint>
#include <ostream>
#include <string>
#include <vector>

#include <boost/log/attributes/mutable_constant.hpp>
#include <boost/log/trivial.hpp>

namespace logging = boost::log;

// clang-format off
#define LOG(lvl)\
    BOOST_LOG_STREAM_WITH_PARAMS(logging::trivial::logger::get(),\
        (set_get_attrib("File", get_filename(__FILE__))) \
        (set_get_attrib("Line", __LINE__)) \
        (set_get_attrib("Func", std::string(__FUNCTION__))) \
        (logging::keywords::severity = logging::trivial::lvl))
// clang-format on

// Set attribute and return the new value
template <typename ValueType>
ValueType set_get_attrib(const char* name, ValueType value) {
    auto attr = logging::attribute_cast<
        logging::attributes::mutable_constant<ValueType>>(
        logging::core::get()->get_thread_attributes()[name]);
    attr.set(value);
    return attr.get();
}

static std::string get_filename(std::string path) {
    return path.substr(path.find_last_of("/\\") + 1);
}

struct sn_record_t {

    // our 32 byte pub keys should always be 52 bytes long in base32z
    static constexpr size_t BASE_LEN = 52;

  private:
    uint16_t port_;
    std::string sn_address_; // Snode address
    std::string pub_key_;
    std::string ip_; // Snode ip
  public:
    sn_record_t(uint16_t port, const std::string& address,
                const std::string& ip)
        : port_(port), ip_(ip) {
        set_address(address);
    }

    sn_record_t() = default;

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
    const std::string& ip() const { return ip_; }
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

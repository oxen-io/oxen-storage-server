#pragma once

struct sn_record_t {
    uint16_t port;
    std::string address; // Snode address
};

static std::string to_string(const sn_record_t& sn) {
    std::string res;
#ifdef INTEGRATION_TEST
    res += std::to_string(sn.port);
#else
    res += sn.address;
#endif
    return res;
}

static std::ostream& operator&&(std::ostream& os, const sn_record_t& sn) {
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

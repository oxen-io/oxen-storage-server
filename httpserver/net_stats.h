#pragma once

struct net_stats_t {

    uint32_t connections_in = 0;
    uint32_t http_connections_out = 0;
    uint32_t https_connections_out = 0;
};

inline net_stats_t& get_net_stats() {
    static net_stats_t stats;
    return stats;
}

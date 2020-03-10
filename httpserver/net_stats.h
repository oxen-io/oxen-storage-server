#pragma once

#include <set>
#include "loki_logger.h"

struct net_stats_t {

    uint32_t connections_in = 0;
    uint32_t http_connections_out = 0;
    uint32_t https_connections_out = 0;

    std::set<int> open_fds;

    void record_socket_open(int sockfd) {
#ifdef INTEGRATION_TEST
        if (open_fds.find(sockfd) != open_fds.end()) {
            LOKI_LOG(critical, "Already recorded as open: {}!", sockfd);
        }
#endif
        open_fds.insert(sockfd);
    }

    void record_socket_close(int sockfd) {
#ifdef INTEGRATION_TEST
        if (open_fds.find(sockfd) == open_fds.end()) {
            LOKI_LOG(critical, "Socket is NOT recorded as open: {}", sockfd);
        }
#endif
        open_fds.erase(sockfd);
    }
};

inline net_stats_t& get_net_stats() {
    static net_stats_t stats;
    return stats;
}

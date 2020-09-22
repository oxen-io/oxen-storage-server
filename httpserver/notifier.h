#pragma once

#include "loki_common.h"
#include <lokimq/lokimq.h>
#include <string_view>
#include <unordered_set>

namespace loki {

class LokimqServer;

class Notifier {

    LokimqServer& lmq_;

    std::unordered_set<std::string> pubkeys_;

    // For now only one connection is allowed for notification server
    boost::optional<lokimq::ConnectionID> cid_;

  public:
    Notifier(LokimqServer& lmq);

    void add_pubkey(const lokimq::ConnectionID& cid, std::string_view pubkey);

    size_t subscriber_count() const;

    template <typename Message>
    void maybe_notify(const Message& msg);
};

} // namespace loki
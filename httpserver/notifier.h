#pragma once

#include <unordered_set>
#include "loki_common.h"
#include <lokimq/lokimq.h>

namespace loki {

class LokimqServer;

class Notifier {

    LokimqServer& lmq_;

    std::unordered_set<std::string> pubkeys_;

    // For now only one connection is allowed for notification server
    boost::optional<lokimq::ConnectionID> cid_;

  public:
    Notifier(LokimqServer& lmq);

    void add_pubkey(const lokimq::ConnectionID& cid, lokimq::string_view pubkey);

    size_t subscriber_count() const;

    template<typename Message>
    void maybe_notify(const Message& msg);
};


} // namespace loki
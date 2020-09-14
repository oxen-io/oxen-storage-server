#include "notifier.h"

#include "lmq_server.h"
#include "loki_logger.h"

#include "Item.hpp"

#include <string_view>

#include "../external/json.hpp"

using nlohmann::json;

namespace loki {

Notifier::Notifier(LokimqServer& lmq) : lmq_(lmq) {}

void Notifier::add_pubkey(const lokimq::ConnectionID& cid,
                             std::string_view pubkey) {

    cid_ = cid;

    this->pubkeys_.insert(pubkey.data());
}

size_t Notifier::subscriber_count() const {
    return this->pubkeys_.size();
}

template <typename Message>
void Notifier::maybe_notify(const Message& msg) {

    LOKI_LOG(trace, "[notify] Maybe notify for pubkey: {}", msg.pub_key);

    if (!cid_) {
        LOKI_LOG(debug, "[notify] Notification connection is missing");
        return;
    }

    if (pubkeys_.find(msg.pub_key) == pubkeys_.end()) {
        return;
    }

    json res_body;
    json messages = json::array();

    json message;
    message["hash"] = msg.hash;
    message["expiration"] = msg.timestamp + msg.ttl;
    message["ttl"] = msg.ttl;
    message["data"] = msg.data;
    res_body["message"] = message;

    lmq_->send(*cid_, "MESSAGE", res_body.dump());
}

template void Notifier::maybe_notify(const storage::Item& msg);

template void Notifier::maybe_notify(const message_t& msg);

} // namespace loki
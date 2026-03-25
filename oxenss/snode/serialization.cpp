#include "serialization.h"

#include <oxenss/logging/oxen_logger.h>
#include <oxenss/utils/string_utils.hpp>
#include <oxenss/utils/time.hpp>

#include <oxenc/base64.h>
#include <oxenc/bt_producer.h>
#include <oxenc/bt_serialize.h>

#include <chrono>
#include <type_traits>

namespace oxenss::snode {

static auto logcat = log::Cat("snode");

static std::pair<std::string, bool> serialize_more_messages(
        const std::function<const message*()>& next_msg) {
    std::pair<std::string, bool> result{"", false};
    auto& [payload, done] = result;

    // We use *two* list producers here to avoid large string reallocations.  What we want
    // is:
    //
    //     \x01l[...][...][...]e
    //
    // and by using a dummy extra out bt_list_producer, we will produce:
    //
    //     ll[...][...][...]ee
    //
    // which we can then change the first `l` to \x01, and drop the final e, without needing
    // to move or reallocate the string.
    oxenc::bt_list_producer fake_outer;
    auto l = fake_outer.append_list();
    bool some = false;
    while (fake_outer.view().size() < SERIALIZATION_BATCH_SIZE) {
        const auto* msg = next_msg();
        if (!msg) {
            done = true;
            break;
        }
        some = true;
        auto item = l.append_list();
        item.append(msg->pubkey.prefixed_raw());
        item.append(msg->hash);
        item.append(to_epoch_ms(msg->timestamp));
        item.append(to_epoch_ms(msg->expiry));
        item.append(msg->data);
        item.append(to_int(msg->msg_namespace));
    }

    if (some) {
        payload = std::move(fake_outer).str();
        payload[0] = SERIALIZATION_VERSION_BT;  // Replace initial l with the version
        payload.pop_back();                     // Drop the unwanted final e
    }

    return result;
}

std::vector<std::string> serialize_messages(
        std::function<const message*()> next_msg, uint8_t version) {
    std::vector<std::string> res;

    if (version == SERIALIZATION_VERSION_BT) {
        bool done;
        std::string payload;
        do {
            std::tie(payload, done) = serialize_more_messages(next_msg);
            if (payload.size() > 3)  // 3 = empty list: '\x01le'
                res.push_back(std::move(payload));
        } while (!done);
    } else {
        log::critical(logcat, "Invalid serialization version {}", +version);
        throw std::logic_error{"Invalid serialization version " + std::to_string(version)};
    }

    return res;
}

std::vector<message> deserialize_messages(std::string_view slice) {
    log::trace(logcat, "=== Deserializing ===");

    // v0 (now unsupported) didn't send a version at all, and sent things incredibly
    // inefficiently. v1+ put the version as the first byte (but can't use any of
    // '0'..'9','a'..'f','A'..'F' because v0 started out with a hex pubkey).
    uint8_t version = 0;
    if (!slice.empty() && slice.front() < '0' && slice.front() != 0) {
        version = slice.front();
        slice.remove_prefix(1);
    }

    if (version != SERIALIZATION_VERSION_BT) {
        log::error(logcat, "Invalid deserialization version {}", +version);
        return {};
    }

    // v1:
    std::vector<message> result;
    oxenc::bt_list_consumer l{slice};
    while (!l.is_finished()) {
        auto& item = result.emplace_back();
        auto m = l.consume_list_consumer();
        if (!item.pubkey.load(m.consume_string_view())) {
            log::debug(logcat, "Unable to deserialize(v1) pubkey");
            return {};
        }
        item.hash = m.consume_string();
        item.timestamp = from_epoch_ms(m.consume_integer<int64_t>());
        item.expiry = from_epoch_ms(m.consume_integer<int64_t>());
        item.data = m.consume_string();
        // TODO: the namespace was missing before 2.11.3, so for now we only load it if there is an
        // extra field in the list.  Once all storage servers are running 2.11.3+ we can remove this
        // `if` and just require the field unconditionally:
        if (!m.is_finished())
            item.msg_namespace = static_cast<namespace_id>(
                    m.consume_integer<std::underlying_type_t<namespace_id>>());
    }

    log::trace(logcat, "=== END ===");

    return result;
}

}  // namespace oxenss::snode

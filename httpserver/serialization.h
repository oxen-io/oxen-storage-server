#pragma once

#include <string>
#include <vector>

namespace service_node {
namespace storage {
class Item;
}
} // namespace service_node

namespace loki {

class message_t;

void serialize_message(std::string& buf, const message_t& msg);

std::vector<std::string> serialize_messages(const std::vector<message_t>& msgs);

/// TODO: reuse the one above
std::string serialize_message(const service_node::storage::Item& msg);

std::vector<message_t> deserialize_messages(const std::string& blob);

} // namespace loki

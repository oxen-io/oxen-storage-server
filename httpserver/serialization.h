#pragma once

#include <string>
#include <vector>

namespace oxen {

namespace storage {
struct Item;
}

struct message_t;

inline constexpr size_t SERIALIZATION_BATCH_SIZE = 9'000'000;

template <typename T>
void serialize_message(std::string& buf, const T& msg);

template <typename T>
std::vector<std::string> serialize_messages(const std::vector<T>& msgs);

std::vector<message_t> deserialize_messages(std::string_view blob);

} // namespace oxen

#include "Storage.hpp"
#include "DatabaseHandler.hpp"
#include <stdio.h>

namespace service_node {

using namespace storage;

Storage::~Storage() {
    // needed for unique_ptr
}

Storage::Storage(const std::string& db_dir) : db(new DatabaseHandler(db_dir)) {}

bool Storage::store(const std::string& hash, const std::string& pubKey,
                    const std::string& bytes, uint64_t ttl) {
    return db->store(hash, pubKey, bytes, ttl);
}

bool Storage::retrieve(const std::string& pubKey, std::vector<Item>& items,
                       const std::string& lashHash) {
    return db->retrieve(pubKey, items, lashHash);
}
} // namespace service_node

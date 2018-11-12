#pragma once

#include "Item.hpp"

#include <memory>
#include <stdint.h>
#include <string>
#include <vector>

class DatabaseHandler;

namespace service_node {

class Storage {
  public:
    Storage(const std::string& db_dir);
    ~Storage();
    bool store(const std::string& hash, const std::string& pubKey,
               const std::string& data, uint64_t ttl);
    bool retrieve(const std::string& pubKey, std::vector<storage::Item>& data,
                  const std::string& lastHash);

  private:
    std::unique_ptr<DatabaseHandler> db;
};

} // namespace service_node

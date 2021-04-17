#pragma once

#include <filesystem>
#include <string>

#include "oxend_key.h"

namespace oxen {

class Security {
  public:
    Security(const legacy_keypair& key_pair,
             const std::filesystem::path& base_path);

    void generate_cert_signature();
    std::string get_cert_signature() const;

  private:
    const legacy_keypair& key_pair_;
    std::string cert_signature_;
    std::filesystem::path base_path_;
};
} // namespace oxen

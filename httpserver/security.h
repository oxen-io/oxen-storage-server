#pragma once

#include <filesystem>
#include <string>

#include "oxend_key.h"

namespace oxen {

class Security {
  public:
    Security(legacy_keypair key_pair,
             std::filesystem::path base_path);

    void generate_cert_signature();
    const std::string& get_cert_signature() const {
        return cert_signature_;
    }

  private:
    legacy_keypair key_pair_;
    std::string cert_signature_;
    std::filesystem::path base_path_;
};
} // namespace oxen

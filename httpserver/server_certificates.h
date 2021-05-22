#pragma once

#include <filesystem>
#include <boost/asio/ssl/context.hpp>

namespace oxen {

void generate_dh_pem(const std::filesystem::path& dh_path);
void generate_cert(const std::filesystem::path& cert_path, const std::filesystem::path& key_path);
void load_server_certificate(const std::filesystem::path& base_path,
                                    boost::asio::ssl::context& ctx);
}

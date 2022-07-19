#pragma once

#include <filesystem>

#include <oxen/log.hpp>

namespace oxen::logging {

void init(const std::filesystem::path& data_dir, oxen::log::Level log_level);

}  // namespace oxen::logging

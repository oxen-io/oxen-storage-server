#pragma once

#include <filesystem>

#include <oxen/log.hpp>

namespace oxenss {
namespace log = oxen::log;
}

namespace oxenss::logging {

void init(const std::filesystem::path& data_dir, oxen::log::Level log_level);

}  // namespace oxenss::logging

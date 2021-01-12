#pragma once

#include "oxen_logger.h"

struct pow_difficulty_t;

namespace oxen {

namespace dns {

std::vector<pow_difficulty_t> query_pow_difficulty(std::error_code& ec);

void check_latest_version();

} // namespace dns
} // namespace oxen

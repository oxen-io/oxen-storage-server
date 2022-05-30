#include "namespace.h"

#include <cassert>
#include <charconv>

namespace oxen {

std::string to_string(namespace_id ns) {
    char buf[6];
    static_assert(NAMESPACE_MIN >= -99'999 && NAMESPACE_MAX <= 999'999);
    auto [ptr, ec] = std::to_chars(std::begin(buf), std::end(buf), to_int(ns));
    assert(ec == std::errc());
    return std::string(std::begin(buf), ptr - std::begin(buf));
}

}  // namespace oxen

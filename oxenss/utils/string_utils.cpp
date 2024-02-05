#include "string_utils.hpp"
#include <fmt/format.h>
#include <cassert>

namespace oxenss::util {

using namespace std::literals;

std::vector<std::string_view> split(std::string_view str, const std::string_view delim, bool trim) {
    std::vector<std::string_view> results;
    // Special case for empty delimiter: splits on each character boundary:
    if (delim.empty()) {
        results.reserve(str.size());
        for (size_t i = 0; i < str.size(); i++)
            results.emplace_back(str.data() + i, 1);
        return results;
    }

    for (size_t pos = str.find(delim); pos != std::string_view::npos; pos = str.find(delim)) {
        if (!trim || !results.empty() || pos > 0)
            results.push_back(str.substr(0, pos));
        str.remove_prefix(pos + delim.size());
    }
    if (!trim || str.size())
        results.push_back(str);
    else
        while (!results.empty() && results.back().empty())
            results.pop_back();
    return results;
}

std::vector<std::string_view> split_any(
        std::string_view str, const std::string_view delims, bool trim) {
    if (delims.empty())
        return split(str, delims, trim);
    std::vector<std::string_view> results;
    for (size_t pos = str.find_first_of(delims); pos != std::string_view::npos;
         pos = str.find_first_of(delims)) {
        if (!trim || !results.empty() || pos > 0)
            results.push_back(str.substr(0, pos));
        size_t until = str.find_first_not_of(delims, pos + 1);
        if (until == std::string_view::npos)
            str.remove_prefix(str.size());
        else
            str.remove_prefix(until);
    }
    if (!trim || str.size())
        results.push_back(str);
    else
        while (!results.empty() && results.back().empty())
            results.pop_back();
    return results;
}

void trim(std::string_view& s) {
    constexpr auto simple_whitespace = " \t\r\n"sv;
    auto pos = s.find_first_not_of(simple_whitespace);
    if (pos == std::string_view::npos) {  // whole string is whitespace
        s.remove_prefix(s.size());
        return;
    }
    s.remove_prefix(pos);
    pos = s.find_last_not_of(simple_whitespace);
    assert(pos != std::string_view::npos);
    s.remove_suffix(s.size() - (pos + 1));
}

std::string lowercase_ascii_string(std::string_view src) {
    std::string result;
    result.reserve(src.size());
    for (char ch : src)
        result += ch >= 'A' && ch <= 'Z' ? ch + ('a' - 'A') : ch;
    return result;
}

std::string short_duration(std::chrono::duration<double> dur) {
    if (dur >= 36h)
        return fmt::format("{:.1f}d", dur / 24h);
    if (dur >= 90min)
        return fmt::format("{:.1f}h", dur / 1h);
    if (dur >= 90s)
        return fmt::format("{:.1f}min", dur / 1min);
    if (dur >= 1s)
        return fmt::format("{:.1f}s", dur / 1s);

    if (dur >= 100ms)
        return fmt::format(u8"{:.0f}ms", dur / 1ms);
    if (dur >= 1ms)
        return fmt::format(u8"{:.1f}ms", dur / 1ms);
    if (dur >= 100us)
        return fmt::format(u8"{:.0f}µs", dur / 1us);
    if (dur >= 1us)
        return fmt::format(u8"{:.1f}µs", dur / 1us);
    if (dur >= 1ns)
        return fmt::format(u8"{:.0f}ns", dur / 1ns);
    return "0s";
}

std::string friendly_duration(std::chrono::nanoseconds dur) {
    std::ostringstream os;
    bool some = false;
    if (dur >= 24h) {
        os << dur / 24h << 'd';
        dur %= 24h;
        some = true;
    }
    if (dur >= 1h || some) {
        os << dur / 1h << 'h';
        dur %= 1h;
        some = true;
    }
    if (dur >= 1min || some) {
        os << dur / 1min << 'm';
        dur %= 1min;
        some = true;
    }
    if (some) {
        // If we have >= minutes then don't bother with fractional seconds
        os << dur / 1s << 's';
    } else {
        double seconds = std::chrono::duration<double>(dur).count();
        os.precision(3);
        if (dur >= 1s)
            os << seconds << "s";
        else if (dur >= 1ms)
            os << seconds * 1000 << "ms";
        else if (dur >= 1us)
            os << seconds * 1'000'000 << u8"µs";
        else
            os << seconds * 1'000'000'000 << "ns";
    }
    return os.str();
}

}  // namespace oxenss::util

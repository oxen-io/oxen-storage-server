#pragma once
#include <filesystem>
#include <string>
#include <string_view>

namespace oxenss::util {

// Reads a file into a string.  Throws on error.
std::string slurp_file(const std::filesystem::path& file);

// Dumps a string to a file, overwriting if it already exists.  Throws on error.
void dump_file(const std::filesystem::path& file, std::string_view content);

}  // namespace oxenss::util

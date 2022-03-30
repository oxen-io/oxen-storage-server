#include "file.hpp"
#include <fstream>

namespace oxen {

std::string slurp_file(const std::filesystem::path& filename) {
    std::ifstream in;
    in.exceptions(std::ifstream::failbit | std::ifstream::badbit);

    in.open(filename, std::ios::binary | std::ios::in | std::ios::ate);
    std::string contents;
    contents.resize(in.tellg());
    in.seekg(0);
    in.read(contents.data(), contents.size());
    auto bytes_read = in.gcount();
    if (static_cast<size_t>(bytes_read) < contents.size())
        contents.resize(bytes_read);
    return contents;
}

void dump_file(const std::filesystem::path& filename, std::string_view contents) {
    std::ofstream out;
    out.exceptions(std::ifstream::failbit | std::ifstream::badbit);
    out.open(filename, std::ios::binary | std::ios::out | std::ios::trunc);
    out.write(contents.data(), contents.size());
}

}  // namespace oxen

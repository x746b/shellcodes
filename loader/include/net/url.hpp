#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <string_view>

namespace research::net {

struct Url {
    std::string scheme;
    std::string host;
    std::uint16_t port = 0;
    std::string path;

    static std::optional<Url> Parse(std::string_view input);
};

} // namespace research::net

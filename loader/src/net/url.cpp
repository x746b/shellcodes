#include "net/url.hpp"

#include <charconv>

namespace research::net {

std::optional<Url> Url::Parse(std::string_view input) {
    const std::size_t scheme_delimiter = input.find("://");
    if (scheme_delimiter == std::string_view::npos) {
        return std::nullopt;
    }

    Url url{};
    url.scheme = std::string(input.substr(0, scheme_delimiter));
    if (url.scheme != "http") {
        return std::nullopt;
    }

    const std::size_t authority_begin = scheme_delimiter + 3;
    const std::size_t path_begin = input.find('/', authority_begin);
    const std::string_view authority = path_begin == std::string_view::npos
        ? input.substr(authority_begin)
        : input.substr(authority_begin, path_begin - authority_begin);

    if (authority.empty()) {
        return std::nullopt;
    }

    const std::size_t port_delimiter = authority.rfind(':');
    if (port_delimiter == std::string_view::npos) {
        url.host = std::string(authority);
        url.port = 80;
    } else {
        url.host = std::string(authority.substr(0, port_delimiter));
        const std::string_view port_text = authority.substr(port_delimiter + 1);
        unsigned int port = 0;
        const auto [ptr, error] = std::from_chars(
            port_text.data(),
            port_text.data() + port_text.size(),
            port);

        if (error != std::errc{} || ptr != port_text.data() + port_text.size() || port > 65535) {
            return std::nullopt;
        }

        url.port = static_cast<std::uint16_t>(port);
    }

    url.path = path_begin == std::string_view::npos ? "/" : std::string(input.substr(path_begin));
    if (url.host.empty()) {
        return std::nullopt;
    }

    return url;
}

} // namespace research::net

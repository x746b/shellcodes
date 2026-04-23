#pragma once

#include "net/url.hpp"

#include <cstddef>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>

namespace research::net {

struct HttpResponse {
    bool ok = false;
    int status_code = 0;
    std::unordered_map<std::string, std::string> headers;
    std::vector<std::byte> body;
    std::string error;
};

class HttpClient {
public:
    HttpResponse Get(const Url& url, std::string_view user_agent) const;
};

} // namespace research::net

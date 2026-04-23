#include "net/http_client_winsock.hpp"

#include <winsock2.h>
#include <ws2tcpip.h>

#include <algorithm>
#include <cctype>
#include <cstring>
#include <sstream>
#include <string>
#include <vector>

namespace research::net {

namespace {

class WinsockSession {
public:
    WinsockSession() {
        ok_ = ::WSAStartup(MAKEWORD(2, 2), &data_) == 0;
    }

    ~WinsockSession() {
        if (ok_) {
            ::WSACleanup();
        }
    }

    bool ok() const {
        return ok_;
    }

private:
    WSADATA data_{};
    bool ok_ = false;
};

std::string ToLower(std::string value) {
    std::transform(value.begin(), value.end(), value.begin(), [](unsigned char ch) {
        return static_cast<char>(std::tolower(ch));
    });
    return value;
}

std::string BuildRequest(const Url& url, std::string_view user_agent) {
    std::ostringstream request;
    request << "GET " << url.path << " HTTP/1.1\r\n";
    request << "Host: " << url.host;
    if (url.port != 80) {
        request << ":" << url.port;
    }
    request << "\r\n";
    request << "User-Agent: " << user_agent << "\r\n";
    request << "Accept: */*\r\n";
    request << "Connection: close\r\n\r\n";
    return request.str();
}

SOCKET ConnectSocket(const Url& url, std::string& error) {
    addrinfo hints{};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    addrinfo* addresses = nullptr;
    const std::string port_text = std::to_string(url.port);
    const int resolve_status = ::getaddrinfo(url.host.c_str(), port_text.c_str(), &hints, &addresses);
    if (resolve_status != 0) {
        error = "getaddrinfo failed";
        return INVALID_SOCKET;
    }

    SOCKET socket_handle = INVALID_SOCKET;
    for (addrinfo* current = addresses; current != nullptr; current = current->ai_next) {
        socket_handle = ::socket(current->ai_family, current->ai_socktype, current->ai_protocol);
        if (socket_handle == INVALID_SOCKET) {
            continue;
        }

        if (::connect(socket_handle, current->ai_addr, static_cast<int>(current->ai_addrlen)) == 0) {
            break;
        }

        ::closesocket(socket_handle);
        socket_handle = INVALID_SOCKET;
    }

    ::freeaddrinfo(addresses);

    if (socket_handle == INVALID_SOCKET) {
        error = "connect failed";
    }

    return socket_handle;
}

bool SendAll(SOCKET socket_handle, const std::string& request, std::string& error) {
    std::size_t total_sent = 0;
    while (total_sent < request.size()) {
        const int sent = ::send(
            socket_handle,
            request.data() + total_sent,
            static_cast<int>(request.size() - total_sent),
            0);

        if (sent == SOCKET_ERROR) {
            error = "send failed";
            return false;
        }

        total_sent += static_cast<std::size_t>(sent);
    }

    return true;
}

bool ReceiveAll(SOCKET socket_handle, std::string& raw_response, std::string& error) {
    char buffer[4096];

    while (true) {
        const int received = ::recv(socket_handle, buffer, sizeof(buffer), 0);
        if (received == 0) {
            return true;
        }

        if (received == SOCKET_ERROR) {
            error = "recv failed";
            return false;
        }

        raw_response.append(buffer, buffer + received);
    }
}

std::vector<std::byte> ToBytes(const std::string& text) {
    std::vector<std::byte> bytes(text.size());
    std::memcpy(bytes.data(), text.data(), text.size());
    return bytes;
}

std::vector<std::byte> DecodeChunked(const std::string& body, std::string& error) {
    std::vector<std::byte> decoded;
    std::size_t cursor = 0;

    while (cursor < body.size()) {
        const std::size_t line_end = body.find("\r\n", cursor);
        if (line_end == std::string::npos) {
            error = "invalid chunk header";
            return {};
        }

        const std::string size_text = body.substr(cursor, line_end - cursor);
        std::size_t chunk_size = 0;
        std::istringstream size_stream(size_text);
        size_stream >> std::hex >> chunk_size;

        if (size_stream.fail()) {
            error = "failed to parse chunk size";
            return {};
        }

        cursor = line_end + 2;
        if (chunk_size == 0) {
            return decoded;
        }

        if (cursor + chunk_size + 2 > body.size()) {
            error = "chunk length exceeds body size";
            return {};
        }

        const auto* chunk_begin = reinterpret_cast<const std::byte*>(body.data() + cursor);
        decoded.insert(decoded.end(), chunk_begin, chunk_begin + chunk_size);
        cursor += chunk_size + 2;
    }

    error = "truncated chunked body";
    return {};
}

HttpResponse ParseResponse(const std::string& raw_response) {
    HttpResponse response{};
    const std::size_t header_end = raw_response.find("\r\n\r\n");
    if (header_end == std::string::npos) {
        response.error = "malformed HTTP response";
        return response;
    }

    const std::string header_block = raw_response.substr(0, header_end);
    const std::string body = raw_response.substr(header_end + 4);
    std::istringstream header_stream(header_block);

    std::string status_line;
    if (!std::getline(header_stream, status_line)) {
        response.error = "missing status line";
        return response;
    }

    if (!status_line.empty() && status_line.back() == '\r') {
        status_line.pop_back();
    }

    std::istringstream status_stream(status_line);
    std::string http_version;
    status_stream >> http_version >> response.status_code;
    if (status_stream.fail()) {
        response.error = "failed to parse status line";
        return response;
    }

    for (std::string line; std::getline(header_stream, line);) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }

        const std::size_t delimiter = line.find(':');
        if (delimiter == std::string::npos) {
            continue;
        }

        std::string name = ToLower(line.substr(0, delimiter));
        std::string value = line.substr(delimiter + 1);
        if (!value.empty() && value.front() == ' ') {
            value.erase(value.begin());
        }

        response.headers.emplace(std::move(name), std::move(value));
    }

    const auto transfer_encoding = response.headers.find("transfer-encoding");
    if (transfer_encoding != response.headers.end() &&
        ToLower(transfer_encoding->second).find("chunked") != std::string::npos) {
        response.body = DecodeChunked(body, response.error);
    } else {
        response.body = ToBytes(body);
    }

    response.ok = response.error.empty() && response.status_code >= 200 && response.status_code < 300;
    return response;
}

} // namespace

HttpResponse HttpClient::Get(const Url& url, std::string_view user_agent) const {
    HttpResponse response{};
    if (url.scheme != "http") {
        response.error = "only plain HTTP is supported in the first-pass scaffold";
        return response;
    }

    WinsockSession session;
    if (!session.ok()) {
        response.error = "WSAStartup failed";
        return response;
    }

    std::string error;
    SOCKET socket_handle = ConnectSocket(url, error);
    if (socket_handle == INVALID_SOCKET) {
        response.error = std::move(error);
        return response;
    }

    const std::string request = BuildRequest(url, user_agent);
    if (!SendAll(socket_handle, request, error)) {
        ::closesocket(socket_handle);
        response.error = std::move(error);
        return response;
    }

    std::string raw_response;
    if (!ReceiveAll(socket_handle, raw_response, error)) {
        ::closesocket(socket_handle);
        response.error = std::move(error);
        return response;
    }

    ::closesocket(socket_handle);
    return ParseResponse(raw_response);
}

} // namespace research::net

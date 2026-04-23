#pragma once

#include <windows.h>

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string>
#include <unordered_map>

namespace research::integrity {

class MappedImage {
public:
    MappedImage() = default;
    ~MappedImage();

    MappedImage(const MappedImage&) = delete;
    MappedImage& operator=(const MappedImage&) = delete;

    MappedImage(MappedImage&& other) noexcept;
    MappedImage& operator=(MappedImage&& other) noexcept;

    static std::optional<MappedImage> OpenReadOnly(const std::wstring& path);

    const std::byte* data() const;
    std::size_t size() const;
    const std::byte* ResolveRva(std::uint32_t rva) const;
    bool IsOpen() const;

private:
    MappedImage(HANDLE file, HANDLE mapping, std::byte* view, std::size_t size);
    void Reset();

    HANDLE file_ = INVALID_HANDLE_VALUE;
    HANDLE mapping_ = nullptr;
    std::byte* view_ = nullptr;
    std::size_t size_ = 0;
};

struct ParsedExports {
    std::unordered_map<std::string, std::uint32_t> by_name;
};

class ExportParser {
public:
    static std::optional<ParsedExports> ParseLoadedModule(HMODULE module);
    static std::optional<ParsedExports> ParseMappedImage(const MappedImage& image);
};

} // namespace research::integrity

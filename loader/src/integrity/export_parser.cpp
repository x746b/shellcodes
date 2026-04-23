#include "integrity/export_parser.hpp"

#include <windows.h>
#include <winnt.h>

#include <algorithm>
#include <functional>

namespace research::integrity {

namespace {

bool ReadHeaders(
    const std::byte* base,
    std::size_t size,
    const IMAGE_DOS_HEADER*& dos_header,
    const IMAGE_NT_HEADERS64*& nt_headers) {
    if (base == nullptr || size < sizeof(IMAGE_DOS_HEADER)) {
        return false;
    }

    dos_header = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
        return false;
    }

    const auto nt_offset = static_cast<std::size_t>(dos_header->e_lfanew);
    if (nt_offset + sizeof(IMAGE_NT_HEADERS64) > size) {
        return false;
    }

    nt_headers = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + nt_offset);
    if (nt_headers->Signature != IMAGE_NT_SIGNATURE) {
        return false;
    }

    if (nt_headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        return false;
    }

    return true;
}

std::optional<ParsedExports> ParseWithResolver(
    const std::byte* base,
    std::size_t size,
    const std::function<const std::byte*(std::uint32_t)>& resolve_rva) {
    const IMAGE_DOS_HEADER* dos_header = nullptr;
    const IMAGE_NT_HEADERS64* nt_headers = nullptr;
    if (!ReadHeaders(base, size, dos_header, nt_headers)) {
        return std::nullopt;
    }

    const auto& export_directory =
        nt_headers->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (export_directory.VirtualAddress == 0 || export_directory.Size == 0) {
        return ParsedExports{};
    }

    const auto* export_table = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(
        resolve_rva(export_directory.VirtualAddress));
    if (export_table == nullptr) {
        return std::nullopt;
    }

    const auto* names = reinterpret_cast<const DWORD*>(resolve_rva(export_table->AddressOfNames));
    const auto* ordinals = reinterpret_cast<const WORD*>(resolve_rva(export_table->AddressOfNameOrdinals));
    const auto* functions = reinterpret_cast<const DWORD*>(resolve_rva(export_table->AddressOfFunctions));

    if (names == nullptr || ordinals == nullptr || functions == nullptr) {
        return std::nullopt;
    }

    ParsedExports parsed{};
    for (DWORD index = 0; index < export_table->NumberOfNames; ++index) {
        const auto* name_ptr = reinterpret_cast<const char*>(resolve_rva(names[index]));
        if (name_ptr == nullptr) {
            continue;
        }

        const WORD ordinal_index = ordinals[index];
        if (ordinal_index >= export_table->NumberOfFunctions) {
            continue;
        }

        const std::uint32_t function_rva = functions[ordinal_index];
        parsed.by_name.emplace(name_ptr, function_rva);
    }

    return parsed;
}

} // namespace

MappedImage::MappedImage(HANDLE file, HANDLE mapping, std::byte* view, std::size_t size)
    : file_(file), mapping_(mapping), view_(view), size_(size) {}

MappedImage::~MappedImage() {
    Reset();
}

MappedImage::MappedImage(MappedImage&& other) noexcept
    : file_(other.file_), mapping_(other.mapping_), view_(other.view_), size_(other.size_) {
    other.file_ = INVALID_HANDLE_VALUE;
    other.mapping_ = nullptr;
    other.view_ = nullptr;
    other.size_ = 0;
}

MappedImage& MappedImage::operator=(MappedImage&& other) noexcept {
    if (this != &other) {
        Reset();
        file_ = other.file_;
        mapping_ = other.mapping_;
        view_ = other.view_;
        size_ = other.size_;

        other.file_ = INVALID_HANDLE_VALUE;
        other.mapping_ = nullptr;
        other.view_ = nullptr;
        other.size_ = 0;
    }

    return *this;
}

std::optional<MappedImage> MappedImage::OpenReadOnly(const std::wstring& path) {
    HANDLE file = ::CreateFileW(
        path.c_str(),
        GENERIC_READ,
        FILE_SHARE_READ,
        nullptr,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);

    if (file == INVALID_HANDLE_VALUE) {
        return std::nullopt;
    }

    LARGE_INTEGER file_size{};
    if (!::GetFileSizeEx(file, &file_size) || file_size.QuadPart <= 0) {
        ::CloseHandle(file);
        return std::nullopt;
    }

    HANDLE mapping = ::CreateFileMappingW(file, nullptr, PAGE_READONLY, 0, 0, nullptr);
    if (mapping == nullptr) {
        ::CloseHandle(file);
        return std::nullopt;
    }

    void* view = ::MapViewOfFile(mapping, FILE_MAP_READ, 0, 0, 0);
    if (view == nullptr) {
        ::CloseHandle(mapping);
        ::CloseHandle(file);
        return std::nullopt;
    }

    return MappedImage(
        file,
        mapping,
        reinterpret_cast<std::byte*>(view),
        static_cast<std::size_t>(file_size.QuadPart));
}

const std::byte* MappedImage::data() const {
    return view_;
}

std::size_t MappedImage::size() const {
    return size_;
}

bool MappedImage::IsOpen() const {
    return view_ != nullptr;
}

const std::byte* MappedImage::ResolveRva(std::uint32_t rva) const {
    const IMAGE_DOS_HEADER* dos_header = nullptr;
    const IMAGE_NT_HEADERS64* nt_headers = nullptr;
    if (!ReadHeaders(view_, size_, dos_header, nt_headers)) {
        return nullptr;
    }

    if (rva < nt_headers->OptionalHeader.SizeOfHeaders && rva < size_) {
        return view_ + rva;
    }

    const auto* section = IMAGE_FIRST_SECTION(nt_headers);
    for (WORD index = 0; index < nt_headers->FileHeader.NumberOfSections; ++index, ++section) {
        const std::uint32_t virtual_address = section->VirtualAddress;
        const std::uint32_t virtual_size = std::max(section->Misc.VirtualSize, section->SizeOfRawData);
        if (rva < virtual_address || rva >= virtual_address + virtual_size) {
            continue;
        }

        const std::uint32_t raw_offset = section->PointerToRawData + (rva - virtual_address);
        if (raw_offset >= size_) {
            return nullptr;
        }

        return view_ + raw_offset;
    }

    return nullptr;
}

void MappedImage::Reset() {
    if (view_ != nullptr) {
        ::UnmapViewOfFile(view_);
        view_ = nullptr;
    }

    if (mapping_ != nullptr) {
        ::CloseHandle(mapping_);
        mapping_ = nullptr;
    }

    if (file_ != INVALID_HANDLE_VALUE) {
        ::CloseHandle(file_);
        file_ = INVALID_HANDLE_VALUE;
    }

    size_ = 0;
}

std::optional<ParsedExports> ExportParser::ParseLoadedModule(HMODULE module) {
    if (module == nullptr) {
        return std::nullopt;
    }

    const auto* base = reinterpret_cast<const std::byte*>(module);
    const auto* dos_header = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) {
        return std::nullopt;
    }

    const auto* nt_headers =
        reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos_header->e_lfanew);
    if (nt_headers->Signature != IMAGE_NT_SIGNATURE ||
        nt_headers->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
        return std::nullopt;
    }

    const auto resolver = [base](std::uint32_t rva) -> const std::byte* {
        return base + rva;
    };

    return ParseWithResolver(base, nt_headers->OptionalHeader.SizeOfImage, resolver);
}

std::optional<ParsedExports> ExportParser::ParseMappedImage(const MappedImage& image) {
    if (!image.IsOpen()) {
        return std::nullopt;
    }

    const auto resolver = [&image](std::uint32_t rva) -> const std::byte* {
        return image.ResolveRva(rva);
    };

    return ParseWithResolver(image.data(), image.size(), resolver);
}

} // namespace research::integrity

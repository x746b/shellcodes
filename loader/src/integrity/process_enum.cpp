#include "integrity/process_enum.hpp"

#include <windows.h>

#include <algorithm>
#include <cctype>
#include <cwctype>
#include <vector>

namespace research::integrity {

namespace {

constexpr NTSTATUS kStatusInfoLengthMismatch = static_cast<NTSTATUS>(0xC0000004L);

std::wstring ToLower(std::wstring_view input) {
    std::wstring lowered;
    lowered.reserve(input.size());

    for (wchar_t ch : input) {
        lowered.push_back(static_cast<wchar_t>(std::towlower(ch)));
    }

    return lowered;
}

} // namespace

std::vector<ProcessEntry> ProcessEnumerator::Snapshot(const native::NativeApi& api) {
    ULONG buffer_size = 1 << 16;
    std::vector<std::byte> buffer;
    bool success = false;

    for (int attempt = 0; attempt < 6; ++attempt) {
        buffer.resize(buffer_size);
        NTSTATUS status = api.NtQuerySystemInformation(
            SystemProcessInformation,
            buffer.data(),
            buffer_size,
            &buffer_size);

        if (NT_SUCCESS(status)) {
            success = true;
            break;
        }

        if (status != kStatusInfoLengthMismatch) {
            return {};
        }
    }

    if (!success || buffer.empty()) {
        return {};
    }

    std::vector<ProcessEntry> entries;
    auto* current = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(buffer.data());

    while (current != nullptr) {
        ProcessEntry entry{};
        entry.pid = static_cast<DWORD>(reinterpret_cast<ULONG_PTR>(current->UniqueProcessId));

        if (current->ImageName.Buffer != nullptr && current->ImageName.Length > 0) {
            entry.image_name.assign(
                current->ImageName.Buffer,
                current->ImageName.Length / sizeof(wchar_t));
        } else {
            entry.image_name = L"<system>";
        }

        entries.push_back(std::move(entry));

        if (current->NextEntryOffset == 0) {
            break;
        }

        current = reinterpret_cast<SYSTEM_PROCESS_INFORMATION*>(
            reinterpret_cast<std::byte*>(current) + current->NextEntryOffset);
    }

    return entries;
}

std::optional<DWORD> ProcessEnumerator::FindPidByImageName(
    const native::NativeApi& api,
    std::wstring_view image_name) {
    const auto entries = Snapshot(api);
    const auto target = ToLower(image_name);

    for (const auto& entry : entries) {
        if (ToLower(entry.image_name) == target) {
            return entry.pid;
        }
    }

    return std::nullopt;
}

} // namespace research::integrity

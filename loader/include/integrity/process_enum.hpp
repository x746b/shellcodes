#pragma once

#include "native/native_api.hpp"

#include <optional>
#include <string>
#include <vector>

namespace research::integrity {

struct ProcessEntry {
    DWORD pid{};
    std::wstring image_name;
};

class ProcessEnumerator {
public:
    static std::vector<ProcessEntry> Snapshot(const native::NativeApi& api);
    static std::optional<DWORD> FindPidByImageName(
        const native::NativeApi& api,
        std::wstring_view image_name);
};

} // namespace research::integrity

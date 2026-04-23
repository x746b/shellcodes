#pragma once

#include "integrity/export_parser.hpp"

#include <windows.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace research::integrity {

enum class HookIndicator {
    None,
    IndirectJump,
    RelativeJump,
    ShortJump,
    AbsoluteThunk,
    ByteMismatch,
    MissingExport,
};

struct FunctionScanResult {
    std::string function_name;
    HookIndicator indicator = HookIndicator::None;
    bool differs_from_reference = false;
    std::array<std::uint8_t, 16> local_bytes{};
    std::array<std::uint8_t, 16> reference_bytes{};
    std::size_t compared_length = 0;
    std::string note;
};

class HookScanner {
public:
    static std::vector<FunctionScanResult> ScanLocalModuleAgainstFile(
        HMODULE local_module,
        const MappedImage& reference_image,
        const std::vector<std::string>& export_names);

    static const char* Describe(HookIndicator indicator);
};

} // namespace research::integrity

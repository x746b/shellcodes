#include "integrity/hook_scanner.hpp"

#include <cstring>

namespace research::integrity {

namespace {

constexpr std::size_t kCompareLength = 16;

HookIndicator DetectPrologue(const std::array<std::uint8_t, 16>& bytes) {
    if (bytes[0] == 0xFF && bytes[1] == 0x25) {
        return HookIndicator::IndirectJump;
    }

    if (bytes[0] == 0xE9) {
        return HookIndicator::RelativeJump;
    }

    if (bytes[0] == 0xEB) {
        return HookIndicator::ShortJump;
    }

    if (bytes[0] == 0x48 && bytes[1] == 0xB8 && bytes[10] == 0xFF && bytes[11] == 0xE0) {
        return HookIndicator::AbsoluteThunk;
    }

    return HookIndicator::None;
}

std::array<std::uint8_t, 16> CopyBytes(const std::byte* source) {
    std::array<std::uint8_t, 16> output{};
    if (source != nullptr) {
        std::memcpy(output.data(), source, output.size());
    }
    return output;
}

} // namespace

std::vector<FunctionScanResult> HookScanner::ScanLocalModuleAgainstFile(
    HMODULE local_module,
    const MappedImage& reference_image,
    const std::vector<std::string>& export_names) {
    std::vector<FunctionScanResult> results;
    results.reserve(export_names.size());

    const auto local_exports = ExportParser::ParseLoadedModule(local_module);
    const auto reference_exports = ExportParser::ParseMappedImage(reference_image);
    if (!local_exports || !reference_exports) {
        return results;
    }

    const auto* local_base = reinterpret_cast<const std::byte*>(local_module);

    for (const auto& export_name : export_names) {
        FunctionScanResult result{};
        result.function_name = export_name;
        result.compared_length = kCompareLength;

        const auto local_it = local_exports->by_name.find(export_name);
        const auto reference_it = reference_exports->by_name.find(export_name);
        if (local_it == local_exports->by_name.end() || reference_it == reference_exports->by_name.end()) {
            result.indicator = HookIndicator::MissingExport;
            result.note = "Export missing from local or reference image";
            results.push_back(std::move(result));
            continue;
        }

        const auto* local_ptr = local_base + local_it->second;
        const auto* reference_ptr = reference_image.ResolveRva(reference_it->second);
        if (reference_ptr == nullptr) {
            result.indicator = HookIndicator::MissingExport;
            result.note = "Reference RVA could not be resolved";
            results.push_back(std::move(result));
            continue;
        }

        result.local_bytes = CopyBytes(local_ptr);
        result.reference_bytes = CopyBytes(reference_ptr);
        result.differs_from_reference =
            std::memcmp(result.local_bytes.data(), result.reference_bytes.data(), kCompareLength) != 0;

        result.indicator = DetectPrologue(result.local_bytes);
        if (result.indicator == HookIndicator::None && result.differs_from_reference) {
            result.indicator = HookIndicator::ByteMismatch;
        }

        if (result.indicator == HookIndicator::None) {
            result.note = "Local prologue matches expected baseline shape";
        } else if (result.differs_from_reference) {
            result.note = "Suspicious entry sequence and prologue differs from mapped baseline";
        } else {
            result.note = "Suspicious entry sequence";
        }

        results.push_back(std::move(result));
    }

    return results;
}

const char* HookScanner::Describe(HookIndicator indicator) {
    switch (indicator) {
    case HookIndicator::None:
        return "clean";
    case HookIndicator::IndirectJump:
        return "indirect jump stub";
    case HookIndicator::RelativeJump:
        return "relative jump stub";
    case HookIndicator::ShortJump:
        return "short jump stub";
    case HookIndicator::AbsoluteThunk:
        return "absolute thunk";
    case HookIndicator::ByteMismatch:
        return "byte mismatch";
    case HookIndicator::MissingExport:
        return "missing export";
    default:
        return "unknown";
    }
}

} // namespace research::integrity

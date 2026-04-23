#pragma once

#include "integrity/hook_scanner.hpp"

#include <cstddef>
#include <filesystem>
#include <string>
#include <vector>

namespace research::telemetry {

struct HttpSummary {
    bool success = false;
    int status_code = 0;
    std::size_t body_size = 0;
    std::string error;
};

struct RunReport {
    std::string reference_path;
    DWORD explorer_pid = 0;
    HttpSummary http;
    std::vector<integrity::FunctionScanResult> scan_results;
};

bool WriteJsonReport(const std::filesystem::path& path, const RunReport& report);

} // namespace research::telemetry

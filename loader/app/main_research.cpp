#include "config.hpp"

#include "integrity/hook_scanner.hpp"
#include "integrity/process_enum.hpp"
#include "native/native_api.hpp"
#include "net/http_client_winsock.hpp"
#include "net/url.hpp"
#include "telemetry/report.hpp"

#include <windows.h>

#include <filesystem>
#include <iostream>
#include <optional>
#include <string>
#include <vector>

namespace {

std::vector<std::string> BuildExportList() {
    std::vector<std::string> exports;
    exports.reserve(app::config::kExportsToInspect.size());

    for (const auto name : app::config::kExportsToInspect) {
        exports.emplace_back(name);
    }

    return exports;
}

} // namespace

int wmain() {
    const auto native_api = research::native::NativeApi::Load();
    if (!native_api) {
        std::wcerr << L"Failed to late-bind native API exports from ntdll.dll\n";
        return 1;
    }

    std::optional<DWORD> explorer_pid =
        research::integrity::ProcessEnumerator::FindPidByImageName(*native_api, L"explorer.exe");

    std::wcout << L"explorer.exe PID: "
               << (explorer_pid ? std::to_wstring(*explorer_pid) : L"not found")
               << L"\n";

    research::telemetry::HttpSummary http_summary{};
    if (const auto parsed_url = research::net::Url::Parse(app::config::kSampleUrl)) {
        research::net::HttpClient client;
        const auto response = client.Get(*parsed_url, app::config::kUserAgent);

        http_summary.success = response.ok;
        http_summary.status_code = response.status_code;
        http_summary.body_size = response.body.size();
        http_summary.error = response.error;

        std::cout << "HTTP probe: "
                  << (response.ok ? "ok" : "failed")
                  << ", status=" << response.status_code
                  << ", body=" << response.body.size() << " bytes\n";
        if (!response.error.empty()) {
            std::cout << "HTTP detail: " << response.error << "\n";
        }
    } else {
        http_summary.error = "Sample URL is invalid";
        std::cout << "Skipping HTTP probe: invalid URL in config\n";
    }

    HMODULE local_ntdll = ::GetModuleHandleW(L"ntdll.dll");
    if (local_ntdll == nullptr) {
        std::wcerr << L"Failed to obtain local ntdll handle\n";
        return 1;
    }

    auto reference_image = research::integrity::MappedImage::OpenReadOnly(app::config::kReferenceNtdllPath);
    if (!reference_image) {
        std::wcerr << L"Failed to map reference image: " << app::config::kReferenceNtdllPath << L"\n";
        return 1;
    }

    const auto scan_results = research::integrity::HookScanner::ScanLocalModuleAgainstFile(
        local_ntdll,
        *reference_image,
        BuildExportList());

    for (const auto& result : scan_results) {
        std::cout << result.function_name << ": "
                  << research::integrity::HookScanner::Describe(result.indicator)
                  << (result.differs_from_reference ? " (prologue differs)" : "")
                  << "\n";
    }

    research::telemetry::RunReport report{};
    report.reference_path = "C:\\Windows\\System32\\ntdll.dll";
    report.explorer_pid = explorer_pid.value_or(0);
    report.http = http_summary;
    report.scan_results = scan_results;

    const auto output_path = std::filesystem::current_path() / "research_report.json";
    if (!research::telemetry::WriteJsonReport(output_path, report)) {
        std::wcerr << L"Failed to write report to " << output_path.wstring() << L"\n";
        return 1;
    }

    std::wcout << L"Report written to " << output_path.wstring() << L"\n";
    return 0;
}

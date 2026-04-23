#include "unhook/unhook.hpp"

#include "integrity/export_parser.hpp"

#include <windows.h>
#include <winnt.h>

#include <cstring>
#include <string>
#include <vector>

namespace research::unhook {

namespace {

// Copy N bytes from clean mapped image back to local ntdll.
bool Patch(void* hooked, const void* clean, std::size_t n) {
    DWORD old = 0;
    if (!VirtualProtect(hooked, n, PAGE_EXECUTE_READWRITE, &old)) {
        return false;
    }
    std::memcpy(hooked, clean, n);
    VirtualProtect(hooked, n, old, &old);
    FlushInstructionCache(GetCurrentProcess(), hooked, n);
    return true;
}

} // namespace

bool IsHooked(const void* api_address) {
    if (!api_address) return false;
    const auto* p = static_cast<const unsigned char*>(api_address);
    // FF 25 = indirect jump
    if (p[0] == 0xFF && p[1] == 0x25) return true;
    // E9 = relative jump
    if (p[0] == 0xE9) return true;
    // EB = short jump
    if (p[0] == 0xEB) return true;
    return false;
}

bool UnhookAll() {
    auto clean_image_opt = integrity::MappedImage::OpenReadOnly(L"C:\\Windows\\System32\\ntdll.dll");
    if (!clean_image_opt.has_value()) {
        return false;
    }
    const auto& clean_image = *clean_image_opt;

    const auto clean_exports_opt = integrity::ExportParser::ParseMappedImage(clean_image);
    if (!clean_exports_opt) {
        return false;
    }

    HMODULE local_ntdll = GetModuleHandleA("ntdll.dll");
    if (!local_ntdll) {
        return false;
    }

    const auto local_exports_opt = integrity::ExportParser::ParseLoadedModule(local_ntdll);
    if (!local_exports_opt) {
        return false;
    }

    const std::vector<std::string> targets = {
        "NtAllocateVirtualMemory",
        "NtProtectVirtualMemory",
        "NtWriteVirtualMemory",
        "NtCreateThreadEx",
        "NtQueueApcThread",
        "NtOpenProcess",
        "NtClose",
        "NtQuerySystemInformation",
        "NtReadVirtualMemory",
        "NtFreeVirtualMemory",
        "NtSuspendThread",
        "NtResumeThread",
        "VirtualAlloc",
        "VirtualProtect",
        "VirtualFree",
    };

    bool any_patched = false;
    constexpr std::size_t kCopyBytes = 24;

    const auto* local_base = reinterpret_cast<const std::byte*>(local_ntdll);

    for (const auto& name : targets) {
        const auto local_it = local_exports_opt->by_name.find(name);
        const auto clean_it = clean_exports_opt->by_name.find(name);
        if (local_it == local_exports_opt->by_name.end() || clean_it == clean_exports_opt->by_name.end()) {
            continue;
        }

        void* local_addr = const_cast<std::byte*>(local_base + local_it->second);
        const void* clean_addr = clean_image.ResolveRva(clean_it->second);
        if (!clean_addr) continue;

        if (IsHooked(local_addr)) {
            if (Patch(local_addr, clean_addr, kCopyBytes)) {
                any_patched = true;
            }
        }
    }

    return any_patched;
}

} // namespace research::unhook

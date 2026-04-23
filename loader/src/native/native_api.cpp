#include "native/native_api.hpp"

#include "integrity/export_parser.hpp"

#include <windows.h>

#include <cstring>

namespace research::native {

namespace {

template <typename FuncT>
FuncT GetExport(HMODULE mod, const char* name) {
    return reinterpret_cast<FuncT>(::GetProcAddress(mod, name));
}

} // namespace

std::optional<NativeApi> NativeApi::Load() {
    HMODULE ntdll = ::GetModuleHandleW(L"ntdll.dll");
    if (ntdll == nullptr) {
        ntdll = ::LoadLibraryW(L"ntdll.dll");
    }
    if (ntdll == nullptr) {
        return std::nullopt;
    }

    NativeApi api{};
    api.NtQuerySystemInformation    = GetExport<NtQuerySystemInformation_t>(ntdll, "NtQuerySystemInformation");
    api.NtQueryInformationProcess   = GetExport<NtQueryInformationProcess_t>(ntdll, "NtQueryInformationProcess");
    api.NtReadVirtualMemory         = GetExport<NtReadVirtualMemory_t>(ntdll, "NtReadVirtualMemory");
    api.NtClose                     = GetExport<NtClose_t>(ntdll, "NtClose");
    api.NtAllocateVirtualMemory     = GetExport<NtAllocateVirtualMemory_t>(ntdll, "NtAllocateVirtualMemory");
    api.NtProtectVirtualMemory      = GetExport<NtProtectVirtualMemory_t>(ntdll, "NtProtectVirtualMemory");
    api.NtWriteVirtualMemory        = GetExport<NtWriteVirtualMemory_t>(ntdll, "NtWriteVirtualMemory");
    api.NtCreateThreadEx            = GetExport<NtCreateThreadEx_t>(ntdll, "NtCreateThreadEx");
    api.NtQueueApcThread            = GetExport<NtQueueApcThread_t>(ntdll, "NtQueueApcThread");
    api.NtOpenProcess               = GetExport<NtOpenProcess_t>(ntdll, "NtOpenProcess");
    api.NtFreeVirtualMemory         = GetExport<NtFreeVirtualMemory_t>(ntdll, "NtFreeVirtualMemory");
    api.NtSuspendThread             = GetExport<NtSuspendThread_t>(ntdll, "NtSuspendThread");
    api.NtResumeThread              = GetExport<NtResumeThread_t>(ntdll, "NtResumeThread");

    if (!api.NtQuerySystemInformation || !api.NtQueryInformationProcess ||
        !api.NtReadVirtualMemory || !api.NtClose) {
        return std::nullopt;
    }
    return api;
}

uint32_t ExtractSyscallNumberFromMappedImage(const research::integrity::MappedImage& clean_image, const char* function_name) {
    const auto exports_opt = integrity::ExportParser::ParseMappedImage(clean_image);
    if (!exports_opt) {
        return 0;
    }

    const auto it = exports_opt->by_name.find(function_name);
    if (it == exports_opt->by_name.end()) {
        return 0;
    }

    const auto* func = clean_image.ResolveRva(it->second);
    if (!func) {
        return 0;
    }

    const auto* p = reinterpret_cast<const unsigned char*>(func);

    // Scan first 32 bytes for syscall pattern:
    // mov r10, rcx (4C 8B D1)
    // mov eax, imm32 (B8 XX XX XX XX)
    // ... optional test/jnz ...
    // syscall (0F 05)
    // ret (C3)
    for (int i = 0; i < 28; ++i) {
        if (p[i] == 0x0F && p[i + 1] == 0x05) {
            // Look backward for B8 xx xx xx xx within reasonable range
            for (int j = 1; j <= 12; ++j) {
                if (i - j >= 0 && p[i - j] == 0xB8) {
                    uint32_t num = 0;
                    std::memcpy(&num, &p[i - j + 1], 4);
                    return num;
                }
            }
        }
    }
    return 0;
}

} // namespace research::native

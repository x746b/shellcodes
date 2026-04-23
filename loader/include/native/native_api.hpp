#pragma once

#include "native/nt_types.hpp"

#include <cstdint>
#include <optional>

namespace research::integrity {
class MappedImage;
}

namespace research::native {

struct NativeApi {
    NtQuerySystemInformation_t NtQuerySystemInformation{};
    NtQueryInformationProcess_t NtQueryInformationProcess{};
    NtReadVirtualMemory_t NtReadVirtualMemory{};
    NtClose_t NtClose{};
    NtAllocateVirtualMemory_t NtAllocateVirtualMemory{};
    NtProtectVirtualMemory_t NtProtectVirtualMemory{};
    NtWriteVirtualMemory_t NtWriteVirtualMemory{};
    NtCreateThreadEx_t NtCreateThreadEx{};
    NtQueueApcThread_t NtQueueApcThread{};
    NtOpenProcess_t NtOpenProcess{};
    NtFreeVirtualMemory_t NtFreeVirtualMemory{};
    NtSuspendThread_t NtSuspendThread{};
    NtResumeThread_t NtResumeThread{};

    static std::optional<NativeApi> Load();
};

// Extract the syscall number from a clean (unhooked) ntdll mapped image.
// Returns 0 if the pattern cannot be found.
uint32_t ExtractSyscallNumberFromMappedImage(const research::integrity::MappedImage& clean_image, const char* function_name);

} // namespace research::native

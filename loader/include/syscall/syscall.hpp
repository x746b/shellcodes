#pragma once

#include "native/nt_types.hpp"

#include <windows.h>

#include <cstdint>
#include <cstddef>

namespace research::syscall {

// Direct-syscall dispatcher: each member is a pointer to a small
// runtime-generated stub (mov r10,rcx / mov eax,NUM / syscall / ret).
struct Dispatcher {
    native::NtAllocateVirtualMemory_t NtAllocateVirtualMemory = nullptr;
    native::NtProtectVirtualMemory_t NtProtectVirtualMemory = nullptr;
    native::NtWriteVirtualMemory_t NtWriteVirtualMemory = nullptr;
    native::NtCreateThreadEx_t NtCreateThreadEx = nullptr;
    native::NtQueueApcThread_t NtQueueApcThread = nullptr;
    native::NtOpenProcess_t NtOpenProcess = nullptr;
    native::NtClose_t NtClose = nullptr;
    native::NtFreeVirtualMemory_t NtFreeVirtualMemory = nullptr;
    native::NtSuspendThread_t NtSuspendThread = nullptr;
    native::NtResumeThread_t NtResumeThread = nullptr;
    native::NtReadVirtualMemory_t NtReadVirtualMemory = nullptr;
    native::NtQuerySystemInformation_t NtQuerySystemInformation = nullptr;
    native::NtQueryInformationProcess_t NtQueryInformationProcess = nullptr;

    // Build all stubs by extracting syscall numbers from the on-disk clean ntdll
    // and allocating one RX page full of trampolines.
    bool Init();

    // Release the stub page (optional cleanup)
    void Shutdown();

private:
    void* stub_page_ = nullptr;
    std::size_t stub_page_size_ = 0;
};

// Global singleton accessor.
Dispatcher& GetDispatcher();

} // namespace research::syscall

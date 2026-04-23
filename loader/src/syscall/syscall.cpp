#include "syscall/syscall.hpp"

#include "native/native_api.hpp"
#include "integrity/export_parser.hpp"

#include <windows.h>

#include <cstring>

namespace research::syscall {

namespace {

// Raw opcode template for a direct syscall trampoline:
//   mov r10, rcx      ; 4C 8B D1
//   mov eax, imm32    ; B8 XX XX XX XX
//   syscall           ; 0F 05
//   ret               ; C3
// Total = 12 bytes.  We pad to 16 for alignment.
constexpr std::size_t kStubSize = 16;

void WriteStub(unsigned char* dst, uint32_t syscall_num) {
    static const unsigned char kTemplate[12] = {
        0x4C, 0x8B, 0xD1,
        0xB8, 0x00, 0x00, 0x00, 0x00,
        0x0F, 0x05,
        0xC3
    };
    std::memcpy(dst, kTemplate, 12);
    std::memcpy(dst + 4, &syscall_num, 4);
    dst[12] = 0x90; // nop padding
    dst[13] = 0x90;
    dst[14] = 0x90;
    dst[15] = 0x90;
}

} // namespace

bool Dispatcher::Init() {
    // Map clean ntdll from disk to extract syscall numbers without touching
    // potentially hooked in-memory ntdll.
    auto clean_image_opt = research::integrity::MappedImage::OpenReadOnly(L"C:\\Windows\\System32\\ntdll.dll");
    if (!clean_image_opt.has_value()) {
        return false;
    }
    const auto& clean_image = *clean_image_opt;

    struct Pair { const char* name; void** out; };
    Pair pairs[] = {
        { "NtAllocateVirtualMemory",    reinterpret_cast<void**>(&NtAllocateVirtualMemory) },
        { "NtProtectVirtualMemory",     reinterpret_cast<void**>(&NtProtectVirtualMemory) },
        { "NtWriteVirtualMemory",       reinterpret_cast<void**>(&NtWriteVirtualMemory) },
        { "NtCreateThreadEx",           reinterpret_cast<void**>(&NtCreateThreadEx) },
        { "NtQueueApcThread",           reinterpret_cast<void**>(&NtQueueApcThread) },
        { "NtOpenProcess",              reinterpret_cast<void**>(&NtOpenProcess) },
        { "NtClose",                    reinterpret_cast<void**>(&NtClose) },
        { "NtFreeVirtualMemory",        reinterpret_cast<void**>(&NtFreeVirtualMemory) },
        { "NtSuspendThread",            reinterpret_cast<void**>(&NtSuspendThread) },
        { "NtResumeThread",             reinterpret_cast<void**>(&NtResumeThread) },
        { "NtReadVirtualMemory",        reinterpret_cast<void**>(&NtReadVirtualMemory) },
        { "NtQuerySystemInformation",   reinterpret_cast<void**>(&NtQuerySystemInformation) },
        { "NtQueryInformationProcess",  reinterpret_cast<void**>(&NtQueryInformationProcess) },
    };

    const std::size_t count = sizeof(pairs) / sizeof(pairs[0]);
    const std::size_t page_size = 4096;
    const std::size_t needed = (count * kStubSize + page_size - 1) & ~(page_size - 1);

    void* page = VirtualAlloc(nullptr, needed, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!page) {
        return false;
    }

    unsigned char* cursor = static_cast<unsigned char*>(page);
    for (const auto& p : pairs) {
        uint32_t num = research::native::ExtractSyscallNumberFromMappedImage(clean_image, p.name);
        if (num == 0) {
            // If we cannot extract one stub, keep going — the caller may fall back
            *p.out = nullptr;
            cursor += kStubSize;
            continue;
        }
        WriteStub(cursor, num);
        *p.out = cursor;
        cursor += kStubSize;
    }

    DWORD old = 0;
    if (!VirtualProtect(page, needed, PAGE_EXECUTE_READ, &old)) {
        VirtualFree(page, 0, MEM_RELEASE);
        return false;
    }
    FlushInstructionCache(GetCurrentProcess(), page, needed);

    stub_page_ = page;
    stub_page_size_ = needed;
    return true;
}

void Dispatcher::Shutdown() {
    if (stub_page_) {
        VirtualFree(stub_page_, 0, MEM_RELEASE);
        stub_page_ = nullptr;
        stub_page_size_ = 0;
    }
    NtAllocateVirtualMemory = nullptr;
    NtProtectVirtualMemory = nullptr;
    NtWriteVirtualMemory = nullptr;
    NtCreateThreadEx = nullptr;
    NtQueueApcThread = nullptr;
    NtOpenProcess = nullptr;
    NtClose = nullptr;
    NtFreeVirtualMemory = nullptr;
    NtSuspendThread = nullptr;
    NtResumeThread = nullptr;
    NtReadVirtualMemory = nullptr;
    NtQuerySystemInformation = nullptr;
    NtQueryInformationProcess = nullptr;
}

Dispatcher& GetDispatcher() {
    static Dispatcher d;
    return d;
}

} // namespace research::syscall

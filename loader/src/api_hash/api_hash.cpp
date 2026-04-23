#include "api_hash/api_hash.hpp"

#include <windows.h>
#include <winnt.h>

#include <cstring>

namespace research::apihash {

namespace {

FARPROC ResolveInModule(HMODULE module, uint32_t target_hash) {
    if (!module) return nullptr;

    const auto* base = reinterpret_cast<const unsigned char*>(module);
    const auto* dos = reinterpret_cast<const IMAGE_DOS_HEADER*>(base);
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) return nullptr;

    const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(base + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) return nullptr;
    if (nt->OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) return nullptr;

    const auto& dd = nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_EXPORT];
    if (dd.Size == 0) return nullptr;

    const auto* exp = reinterpret_cast<const IMAGE_EXPORT_DIRECTORY*>(base + dd.VirtualAddress);
    const auto* names = reinterpret_cast<const DWORD*>(base + exp->AddressOfNames);
    const auto* ords = reinterpret_cast<const WORD*>(base + exp->AddressOfNameOrdinals);
    const auto* funcs = reinterpret_cast<const DWORD*>(base + exp->AddressOfFunctions);

    for (DWORD i = 0; i < exp->NumberOfNames; ++i) {
        const char* name = reinterpret_cast<const char*>(base + names[i]);
        if (HashDjb2(name) == target_hash) {
            WORD ord = ords[i];
            if (ord >= exp->NumberOfFunctions) continue;
            return reinterpret_cast<FARPROC>(const_cast<unsigned char*>(base + funcs[ord]));
        }
    }
    return nullptr;
}

} // namespace

FARPROC ResolveByHash(HMODULE module, uint32_t target_hash) {
    return ResolveInModule(module, target_hash);
}

FARPROC ResolveNtdll(uint32_t hash) {
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    if (!ntdll) ntdll = LoadLibraryA("ntdll.dll");
    return ResolveInModule(ntdll, hash);
}

} // namespace research::apihash

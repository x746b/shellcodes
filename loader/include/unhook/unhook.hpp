#pragma once

#include <windows.h>

namespace research::unhook {

// Restore clean prologues for critical ntdll exports by copying from the
// on-disk reference ntdll.dll (C:\Windows\System32\ntdll.dll).
// Returns true if at least one API was patched successfully.
bool UnhookAll();

// Check whether the first bytes of an API look like an EDR hook stub.
// Detects: FF 25 (indirect jmp), E9 (rel jmp), EB (short jmp).
bool IsHooked(const void* api_address);

} // namespace research::unhook

#pragma once

namespace research::evasion {

// Check if running inside a known VM / hypervisor.
bool IsVmDetected();

// Check if a debugger is attached (multiple methods).
bool IsDebuggerDetected();

// Check sandbox artefacts (low resources, generic username, etc.).
bool IsSandboxDetected();

// Combined gate: true → abort execution.
bool ShouldAbort();

// Initial jitter delay (30–120 s) + secondary micro-delays.
void JitterDelay();

} // namespace research::evasion

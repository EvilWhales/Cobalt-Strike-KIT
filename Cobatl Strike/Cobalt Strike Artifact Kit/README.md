# Rust Cobalt Strike Artifact Kit

[![Release](https://img.shields.io/github/v/release/SilentStrikeLab/Rust-Cobalt-Strike-Artifact-Kit?include_prereleases&sort=semver)](https://github.com/SilentStrikeLab/Rust-Cobalt-Strike-Artifact-Kit/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)
[![Rustc](https://img.shields.io/badge/rustc-nightly-blue)](#requirements)
[![Platform](https://img.shields.io/badge/platform-Windows%20x64-informational)](#requirements)
[![Maintenance](https://img.shields.io/maintenance/yes/2025)](#)

---

##  Disclaimer
This repository is for **defensive research and education only**. It is intended to help blue teams and detection engineers understand telemetry and build signatures around loader-like behavior. **Use only in isolated labs you own/control.** The maintainers are **not responsible** for misuse.

---

## Overview
A Rust-based loader research project that demonstrates (at a high level) you can read [SilentStrike Full Research](https://blog.silentstrike.io/posts/Advanced-Evasion-in-Rust-ArtifactKit/) for more details:

- **API Hashing** via a DJB2-style algorithm (compile-time constants) to avoid static strings.
- **Process Discovery** of a trusted service (e.g., `spoolsv.exe`) to illustrate PID enumeration patterns.
- **Section Mapping (RW→RX)** using `NtCreateSection`/`NtMapViewOfSection` for permission transitions.
- **Fiber Execution** (Convert→Create→Switch) for stealth-style execution telemetry without creating new threads.
- **“Hell’s Gate”** concept for direct syscall index resolution (documented; treat responsibly).
- **Payload Obfuscation** (XOR rotating key) within an embedded `Phear` structure.

> Notes:
> * The code is for research and may include stubs/guards to prevent weaponization.
> * Any process-injection discussion is for **defensive analysis** only.

---

## Features
- **API Hashing:** Compile-time hashing for exports (no plaintext function names).
- **Process Enumeration:** Finds `spoolsv.exe` (Print Spooler) PID as a demo target.
- **Section Mapping:** Separates write and execute views (RW→RX) to avoid RWX.
- **Fiber Trampoline:** Converts current thread to a fiber and switches to a benign entry.
- **Syscall Concept (“Hell’s Gate”):** Direct index resolution concept (avoid userland hooks) — keep **lab-only**.
- **Phear Payload Container:** Fixed-size embedded buffer, patchable via external tool for controlled demos.

<img width="1076" height="599" alt="image" src="https://github.com/user-attachments/assets/abad429a-40cb-4d74-a362-f524616edbb5" />

---

## Bitdefender Test

<img width="1982" height="680" alt="image" src="https://github.com/user-attachments/assets/cd0e9d5a-bf7d-40fb-bd6f-67ead8fec4d9" />

---

## Scan Results

* [Static Scan Results](https://kleenscan.com/scan_result/2391061e53d2e99d98142946c94eec4d8a28fb6d9e51dc455934d1ca782277c8)

* [Runtime Scan Results](https://kleenscan.com/runtime/scan_result/c5d877bcea52c6dd586121d24b572968f09461312ed371d9fdfc9b7505aadaeb)


----

## Requirements
- **OS:** Windows 10/11 (x64)
- **Toolchain:** Rust nightly (for inline `asm!`) — see build matrix for alternatives
- **SDK:** MSVC Build Tools / Windows SDK

---

## Build
```bash
# Nightly toolchain
rustup default nightly
cargo build --release

# Or with stable (feature-gated, if available)
cargo build --release --features stable
```

---

## Usage
1. (Optional) Patch the embedded `Phear` buffer using your CNA/tooling.
2. Ensure **Print Spooler** (`spoolsv.exe`) is running.
3. Run the loader:
   ```bash
   cargo run --release
   ```
4. Expected behavior (research demo):
   - Locate `spoolsv.exe` PID
   - Detect CNA patch state
   - Create/Map a section (RW, then RX)
   - Convert thread → fiber, create a fiber, switch to benign entry

> **Important:** Keep testing in a controlled lab. Do **not** run on production/end-user systems.

---

## Payload Structure (`Phear`)
```rust
#[repr(C)]
pub struct Phear {
    pub offset: i32,         // Payload offset
    pub length: i32,         // Payload length
    pub key: [u8; 8],        // XOR key (rotating)
    pub gmh_offset: i32,     // GetModuleHandle offset (if used)
    pub gpa_offset: i32,     // GetProcAddress offset (if used)
    pub payload: [u8; 447702]// Encrypted/placeholder payload
}
```
- The binary embeds a static `Phear` buffer (placeholder data by default).
- External tooling (e.g., CNA) can patch `offset/length/key/payload` for benign demos.
- Replace the build bin with Artifact Kit artifact64big.exe

---

## Technical Notes
### API Hashing
- DJB2-style hashing avoids string-based IOC signatures.
- Hashes are compared against export names resolved at runtime.

### Memory Protection & Section Mapping
- Demonstrates the **RW→RX** transition using sections to avoid direct RWX.
- Separate RW view for copying, RX view for execution-like telemetry.

### Fiber Execution
- Uses `ConvertThreadToFiber` → `CreateFiber` → `SwitchToFiber`.
- Enables telemetry without new thread creation (useful for detections).

### Detection Opportunities (for Blue Teams)
- Anomalous export resolution patterns / PEB access.
- Section mapping with immediate permission transitions.
- Thread-to-fiber conversion frequency and call graph.
- RW and RX views mapped from same section within short intervals.
- Abnormal interaction with `spoolsv.exe` (or other system services).

---

## Troubleshooting
- **`Failed to find spoolsv.exe process`**: Ensure Print Spooler is enabled and running.
- **Inline asm errors on stable**: Use nightly (`rustup default nightly`) or enable a `stable` feature variant if present.
- **AV/EDR blocks**: Expected in monitored environments—review telemetry; test in an isolated lab.
---

## Contributing
PRs focused on **defensive visibility**, **telemetry**, and **documentation** are welcome. Avoid adding weaponized functionality.



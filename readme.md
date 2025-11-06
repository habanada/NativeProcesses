<p align="center">
  <img src="https://raw.githubusercontent.com/habanada/NativeProcesses/refs/heads/dev/Logo.png" alt="NativeProcesses Logo" width="200">
</p>
<p align="center">
  <b>High-performance .NET 4.8 framework</b> for real-time Windows process monitoring, control, and analysis — including secure remote communication over TLS.
</p>

<p align="center">
  Developed in <b>C# 7.3</b> · Targeting <b>.NET Framework 4.8</b> · GUI: <b>WinForms</b>
</p>

# NativeProcesses Framework

A modular, high-performance .NET framework for real-time monitoring, control, and analysis of Windows processes - 
including secure remote communication support over TLS.

Developed in **C# 7.3**, targeting **.NET Framework 4.8**, with **WinForms** used for demonstration simplicity.

---

## Introduction

**NativeProcesses** is a high-performance, event-driven alternative to the standard `System.Diagnostics.Process` class. 
It bypasses the overhead and limitations of WMI and standard APIs by directly invoking low-level Windows system calls (P/Invoke). 
The framework uses `ntdll.dll`, `kernel32.dll`, `advapi32.dll`, and **Event Tracing for Windows (ETW)** to collect precise, real-time information about processes, threads, CPU, I/O, and security.

In addition to local process management, it provides a **secure TCP/TLS-based network abstraction** that allows remote process viewing and control.

---

## Architecture Overview

```

┌──────────────────────────────────────────┐
│ Application Layer (WinForms, Services) │
│ e.g. ProcessInfoViewModel, RemoteClient │
└──────────────────┬──────────────────────┘
 │
 IProcessNotifier
┌──────────────────▼──────────────────────┐
│ ProcessService (central hub) │
│ Aggregates, caches, raises events │
└──────────────────┬──────────────────────┘
 │
 IProcessEventProvider
┌──────────────────▼──────────────────────┐
│ Provider Layer │
│ Polling, ETW, WMI, Hybrid providers │
└──────────────────┬──────────────────────┘
 │
┌──────────────────▼──────────────────────┐
│ NativeProcessLister, ManagedProcess │
│ Direct Windows API (P/Invoke) access │
└──────────────────┬──────────────────────┘
 │
 Windows Kernel APIs

```

---

## ️ Core Layer - `NativeProcesses.Core`

### ProcessService

**Purpose:** The central class consumed by applications. 
It acts as the hub and façade for process information management.

**Responsibilities:**
1. Subscribes to a provider implementing `IProcessEventProvider`.
2. Maintains an in-memory cache (`ConcurrentDictionary<int, FullProcessInfo>`).
3. Exposes clean, thread-safe events: 
 - `ProcessAdded` 
 - `ProcessRemoved` 
 - `ProcessUpdated`
4. Asynchronously loads additional data (command line, signatures, mitigation info) without blocking updates.
5. Smooths CPU usage data via exponential moving average (EMA) for a more stable UI.

---

### ️ Provider System

Providers deliver process data from different sources and can be freely swapped or combined.

#### `PollingProcessProvider`
- Periodically queries all processes using `NtQuerySystemInformation` from `ntdll.dll`.
- Computes CPU usage precisely by comparing cumulative `KernelTime` and `UserTime` between snapshots, normalized by elapsed time and CPU count.
- Provides memory, thread, and I/O counters.
- Drawback: delayed detection of process start/stop events (poll interval dependent).

#### `EtwProcessProvider`
- Subscribes to **Event Tracing for Windows (ETW)** kernel events: 
 `Kernel.ProcessStart`, `Kernel.ProcessStop`, `Kernel.DiskIORead`, and `Kernel.DiskIOWrite`.
- Delivers real-time process creation and termination notifications with extremely low overhead.
- Captures cumulative I/O byte counts per process.

#### `WmiProcessProvider`
- Uses WMI `__InstanceCreationEvent` and `__InstanceDeletionEvent` for start/stop detection.
- Higher overhead than ETW; serves as a fallback.

#### `HybridProcessProvider`
- Combines multiple providers, typically ETW for instant events and Polling for regular metric updates.
- Merges their event streams to provide best of both worlds.

---

### Low-Level Access Layer

#### `NativeProcessLister`
- Enumerates all processes and threads using the native `NtQuerySystemInformation(SystemProcessInformation)` call.
- Parses internal structs (`SYSTEM_PROCESS_INFORMATION`, `SYSTEM_THREAD_INFORMATION`).
- Performance: comparable to Task Manager, near-zero allocations.

#### `ManagedProcess`
Encapsulates a process handle (`IntPtr`) and provides:

| Operation | Description |
|------------|--------------|
| `Kill()` | Calls `TerminateProcess` |
| `Suspend()` | Calls `NtSuspendProcess` |
| `Resume()` | Calls `NtResumeProcess` |
| `SetPriority()` | Invokes `SetPriorityClass` |
| `GetExePath()` | Reads executable path via `QueryFullProcessImageName` |
| `GetCommandLine()` | Reads target process's PEB (`ReadProcessMemory`) to extract the command line |
| `GetSecurityInfo()` | Fetches user name, integrity level, elevation (via `OpenProcessToken`) |
| `GetMitigationInfo()` | Retrieves security mitigations via `GetProcessMitigationPolicy` (DEP, ASLR, CFG) |
| `GetIoCounters()` | Uses `NtQueryInformationProcess` to fetch process I/O counters |

#### `SignatureVerifier`
- Validates digital signatures of executables.
- Uses the `WinVerifyTrust` API and CryptoAPI calls (`CryptQueryObject`) to extract signer details such as publisher name (e.g., "Microsoft Corporation").

---

### Data Models

| Class | Description |
|--------|--------------|
| `FullProcessInfo` | Central thread-safe container holding all process metadata |
| `ThreadInfo` | Represents individual thread details |
| `ProcessSecurityInfo` | Security descriptor (user, integrity, elevation) |
| `ProcessMitigationInfo` | DEP, ASLR, CFG, etc. |
| `ProcessSignatureInfo` | Digital signature verification results |

---

## Network Layer - `NativeProcesses.Network`

### SecureTcpServer
- Uses `TcpListener` with `SslStream` for encrypted TLS 1.2 connections.
- Client authentication via token string.
- Messages serialized as JSON, compressed via `DeflateStream`.
- Sends broadcasts to all connected clients.

### SecureTcpClient
- Connects securely using `SslStream`.
- Authenticates using a pre-shared token.
- Sends commands (`kill`, `suspend`, `resume`, `get_all_processes`).
- Receives live process updates and process lists.

### ProcessNetworkHost
Server-side bridge between `ProcessService` and network clients:
1. Subscribes to `ProcessService` events (`ProcessAdded`, `ProcessUpdated`, `ProcessRemoved`).
2. Broadcasts changes using compact JSON objects (`ProcessVolatileUpdate`).
3. Handles incoming client commands and executes corresponding operations (`ProcessManager.Kill`, etc.).

---

## ️ Example Applications

### 1. Local Process Viewer (`processlist`)
A WinForms-based local Task Manager built for demonstration purposes.

Features:
- Live display of all processes (name, PID, user, CPU, memory, I/O)
- Thread-level view and control (suspend/resume)
- Context menu for process actions
- Dark title bar (Windows 10+)
- Real-time data binding using `BindingList<ProcessInfoViewModel>`

Start locally:
```bash
processlist.exe
````

### 2. Remote Process Server

A console app hosting the `ProcessService` over TCP/TLS.

```csharp
var cert = new X509Certificate2("server.pfx", "password");
var provider = new PollingProcessProvider(TimeSpan.FromSeconds(3));
var service = new ProcessService(provider);
var server = new SecureTcpServer(5050, cert, "myToken");
var host = new ProcessNetworkHost(service, server, provider);

await server.StartAsync();
service.Start();
```

### 3. Remote Process Viewer

Connects to the remote server and displays real-time process information.

```csharp
var client = new SecureTcpClient("192.168.1.10", 5050, "myToken");
if (await client.ConnectAsync())
{
 await client.SendMessageAsync("get_all_processes", null);
}
```

---

## Technical Details

| Component | Technology |
| ---------------- | ----------------------------------------- |
| Language | C# 7.3 |
| Framework | .NET Framework 4.8 |
| GUI | WinForms |
| Network | TCP/TLS 1.2 + Deflate + JSON |
| Architecture | Provider-based, asynchronous, thread-safe |
| OS Compatibility | Windows 10/11 (x64) |

---

## Repository Layout

```
NativeProcesses.Core/
├── ProcessService.cs
├── PollingProcessProvider.cs
├── ManagedProcess.cs
├── NativeProcessLister.cs
├── SignatureVerifier.cs
└── ...

NativeProcesses.Network/
├── SecureTcpServer.cs
├── SecureTcpClient.cs
├── ProcessNetworkHost.cs
└── ...

processlist/
├── MainForm.cs
├── ProcessInfoViewModel.cs
├── DarkTitleBarHelper.cs
└── ...
```

---

## Quickstart

### Local Demo

1. Set **`processlist`** as the startup project
2. Build with Visual Studio 2019+
3. Run → Task-Manager-style interface opens

### Remote Demo

1. Generate an SSL certificate (`server.pfx`)
2. Start the remote server
3. Connect using the remote client

---

## Developer Notes & Known Issues

The framework is fully functional and stable, but a few areas are still being refined:

| Area | Description | Status |
| ------------------------ | ---------------------------------------------------------------------------------------------------- | --------------------- |
| **Exception Handling** | Some "empty" or overly broad `try/catch` blocks exist and need to be tightened. | Planned |
| **Log Noise** | Frequent `"Failed to get ... pid ..."` logs appear; logging will be throttled and made configurable. | Improving |
| **Async Detail Loading** | `LoadSlowDetails()` spawns many concurrent background tasks; concurrency limiting will be added. | Under review |
| **Thread List Refresh** | Thread data currently replaces full lists instead of diff updates. | To be optimized |
| **Unit Testing** | Coverage is low but test scaffolding is ready. | Expanding |
| **WMI Provider** | Stable but slower; remains an optional fallback to ETW. | Working as intended |

Despite these internal "construction zones", **the framework operates reliably** and all major subsystems -
local monitoring, remote communication, security info, and ETW-based events - function correctly.

---

## License & Author

This project is licensed under the **GNU General Public License v3.0 (GPLv3)**.

You are free to use, modify, and distribute this software under the terms of the GPLv3. 
Any derivative work or redistributed version must also remain open-source under the same license.

For the full license text, see the [LICENSE](./LICENSE) file or visit: 
[https://www.gnu.org/licenses/gpl-3.0.html](https://www.gnu.org/licenses/gpl-3.0.html)


---

## Feedback

Contributions, code reviews, and performance reports are welcome.
The goal of **NativeProcesses** is to remain a **transparent, native, and efficient** Windows process management library for developers.

---

**Author:** Selahattin Erkoc
**Project:** NativeProcesses Framework
**Version:** 1.0.0 (2025)

<p align="center">
  ⭐ If you find this project useful, consider giving it a star on GitHub!  
</p>

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

## Why NativeProcesses is Different

Most .NET process libraries rely on `System.Diagnostics.Process` or WMI,
which are limited in detail and performance. **NativeProcesses** takes a different approach:
it communicates directly with the Windows kernel using low-level NT APIs.

This enables:

* **Real-time process and thread information** with Task Manager-level speed
* **Full control** over processes (suspend, resume, kill, priority, I/O, security)
* **Event-driven updates** through ETW (no polling delays)
* **Optional secure remote access** over **TLS**

Although originally built for **.NET Framework 4.8**,
the codebase also runs under **.NET Core / .NET 6+** with minimal adjustments,
making it suitable for both legacy and modern Windows environments.

**In short:** NativeProcesses gives developers a complete, high-performance foundation
for building advanced Task-Manager-style tools - something rarely found in any other open-source .NET project.

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

````

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
4. Asynchronously loads additional data (command line, signatures, etc.) using a dedicated, rate-limited producer-consumer queue to prevent ThreadPool starvation and ensure UI/network responsiveness.
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
2. Broadcasts a lightweight `ProcessVolatileUpdate` object for `OnProcessUpdated` events to minimize network traffic.
3. Sends the full `FullProcessInfo` object only when a process is added (`OnProcessAdded`) or when a client requests the full list.
4. Handles incoming client commands and executes corresponding operations (`ProcessManager.Kill`, etc.).

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

### 2\. Remote Process Server

A console app hosting the `ProcessService` over TCP/TLS.

```csharp
// Load certificate and set port/token
var cert = new X509Certificate2("cert.pfx", "password");
int port = 8888;
string token = "MySecretToken";

// Setup dependencies
var provider = new PollingProcessProvider(TimeSpan.FromSeconds(3));
var logger = new ConsoleLogger(); // Requires a logger implementation
var service = new ProcessService(provider, logger);

// Set which details to load (can be changed live)
service.DetailOptions.LoadSignatureInfo = true;
service.DetailOptions.LoadMitigationInfo = true;

// Setup and start the server
var server = new SecureTcpServer(port, cert, token, logger);
var hostInstance = new ProcessNetworkHost(service, server, provider);

service.Start();
_ = server.StartAsync(); // Run server in background

Console.ReadLine(); // Wait for exit
hostInstance.ShutdownServer();
```

### 3\. Remote Process Viewer

Connects to the remote server and displays real-time process information.

```csharp
var client = new SecureTcpClient("127.0.0.1", 8888, "MySecretToken");
if (await client.ConnectAsync())
{
 // Request the full process list on connect
 await client.SendMessageAsync("get_all_processes", null);
}
```

-----

### Network Security & Certificate Validation

The framework's `SecureTcpClient` implements **Certificate Pinning** by default to prevent Man-in-the-Middle (MITM) attacks. It works by:

1.  Loading a public `.cer` file (`server.cer`) in its directory (you get it from the server by exporting it **without private key**\!).
2.  Comparing the **thumbprint** of the server's presented certificate with the thumbprint of the known `.cer` file.
3.  Only allowing the connection if the thumbprints match, ensuring the client is talking to the correct server.

-----

## Technical Details

| Component | Technology |
| ---------------- | ----------------------------------------- |
| Language | C\# 7.3 |
| Framework | .NET Framework 4.8 |
| GUI | WinForms |
| Network | TCP/TLS 1.2 + Deflate + JSON |
| Architecture | Provider-based, asynchronous, thread-safe |
| OS Compatibility | Windows 10/11 (x64) |

-----

## Dependencies

**NativeProcesses** is lightweight and only depends on a few external libraries.
All other functionality is implemented in pure **C\# 7.3** using built-in .NET Framework 4.8 APIs.

| Dependency | Purpose | Required |
| -------------------------------------------- | -------------------------------------------------------------------------- | ------------------------------ |
| **Newtonsoft.Json** | JSON serialization for TLS-based network communication |  Yes |
| **Microsoft.Diagnostics.Tracing.TraceEvent** | Real-time kernel event tracing (ETW) for process start/stop and I/O events | ️ Optional (for ETW provider) |
| **System.Management** | WMI provider fallback for environments without ETW | ️ Optional |
| **.NET Framework 4.8** | Base runtime (WinForms, TCP, TLS, Compression, Tasks) |  Yes |

Install required NuGet packages:

```bash
Install-Package Newtonsoft.Json
Install-Package Microsoft.Diagnostics.Tracing.TraceEvent
```

All other namespaces such as `System.Net.Sockets`, `System.Security.Cryptography.X509Certificates`, and
`System.IO.Compression` are included in the .NET Framework 4.8 base class library.

-----

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

processlist/ (Local Demo)
├── MainForm.cs
├── ProcessInfoViewModel.cs
├── DarkTitleBarHelper.cs
└── ...

RemoteClient/ (Network Demo)
├── MainForm.cs
├── ProcessInfoViewModel.cs
└── ...

Server/ (Network Demo)
├── Program.cs
└── ...
```

-----

## Quickstart

### Local Demo

1.  Set **`processlist`** as the startup project
2.  Build with Visual Studio 2019+
3.  Run → Task-Manager-style interface opens

### Remote Demo

1.  Generate an SSL certificate (`cert.pfx` and `server.cer`)
2.  Set **`Server`** as the startup project and run it.
3.  Set **`RemoteClient`** as the startup project and run it.
4.  Click "Connect" in the client.

#### 1\. Create the Certificate (PowerShell)

Run **PowerShell as Administrator** and execute the following command to create a new self-signed certificate in your personal store:

```powershell
New-SelfSignedCertificate -DnsName "localhost" -CertStoreLocation "cert:\CurrentUser\My" -FriendlyName "NativeProcessServerCert" -KeyUsage DigitalSignature, KeyEncipherment
```

*Note: You can replace `"localhost"` with your server's IP address or DNS name if needed.*

-----

#### 2\. Export the Certificates (certmgr.msc)

1.  Press `Win + R`, type `certmgr.msc`, and press **Enter**.
2.  Navigate to **Personal** → **Certificates**.
3.  Locate the certificate you just created (e.g., "localhost").

-----

**A. Export `.pfx` (for the Server):**

1.  Right-click the certificate → **All Tasks** → **Export...**
2.  Select **"Yes, export the private key"**.
3.  Use the default export format (PFX).
4.  Set a **password** (for example, `password`, as used in the demo code).
5.  Save the file as `cert.pfx` inside your **`Server`** project's output directory (e.g., `Server/bin/Debug/cert.pfx`).

-----

**B. Export `.cer` (for the Client):**

1.  Right-click the certificate again → **All Tasks** → **Export...**
2.  Select **"No, do not export the private key"**.
3.  Choose **"Base-64 encoded X.509 (.CER)"** as the export format.
4.  Save the file as `server.cer` inside your **`RemoteClient`** project's output directory (e.g., `RemoteClient/bin/Debug/server.cer`).

## Developer Notes & Known Issues

The framework is fully functional and stable, but a few areas are still being refined:

| Area | Description | Status |
| ------------------------ | ---------------------------------------------------------------------------------------------------- | --------------------- |
| **Exception Handling** | Vague `try/catch` blocks have been refined ("Exception Denoise") to improve stability. | ✅ **Done** |
| **Log Noise** | Throttled and "denoised" logging to remove repetitive "Access Denied" errors. | ✅ **Done** |
| **Async Detail Loading** | `LoadSlowDetails()` now uses a dedicated producer-consumer queue to prevent ThreadPool starvation. | ✅ **Done** |
| **Thread List Refresh** | Thread data currently replaces full lists instead of diff updates. | To be optimized |
| **Unit Testing** | Coverage is low but test scaffolding is ready. | Expanding |
| **WMI Provider** | Stable but slower; remains an optional fallback to ETW. | Working as intended |

Despite these internal "construction zones", **the framework operates reliably** and all major subsystems -
local monitoring, remote communication, security info, and ETW-based events - function correctly.

-----

## License & Author

This project is licensed under the **GNU General Public License v3.0 (GPLv3)**.

You are free to use, modify, and distribute this software under the terms of the GPLv3.
Any derivative work or redistributed version must also remain open-source under the same license.

For the full license text, see the [LICENSE](https://www.google.com/search?q=./LICENSE) file or visit:
[https://www.gnu.org/licenses/gpl-3.0.html](https://www.gnu.org/licenses/gpl-3.0.html)

-----

## Feedback

Contributions, code reviews, and performance reports are welcome.
The goal of **NativeProcesses** is to remain a **transparent, native, and efficient** Windows process management library for developers.

-----

**Author:** Selahattin Erkoc
**Project:** NativeProcesses Framework
**Version:** 1.0.0 (2025)

-----

## Third-Party Notices

This project makes use of third-party libraries distributed under open-source licenses.
Their original license terms and copyright notices are retained below as required by their respective authors.

### Newtonsoft.Json

Copyright © James Newton-King
Licensed under the [MIT License](https://licenses.nuget.org/MIT)

### Microsoft.Diagnostics.Tracing.TraceEvent

Copyright © Microsoft Corporation
Licensed under the [MIT License](https://licenses.nuget.org/MIT)

These components are redistributed in binary form only and have not been modified.
No ownership or endorsement by the original authors is implied.

-----

\<p align="center"\>
⭐ If you find this project useful, consider giving it a star on GitHub\!  
\</p\>

```

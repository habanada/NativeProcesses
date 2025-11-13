<p align="center">
<img src="[https://raw.githubusercontent.com/habanada/NativeProcesses/refs/heads/dev/Logo.png](https://raw.githubusercontent.com/habanada/NativeProcesses/refs/heads/dev/Logo.png)" alt="NativeProcesses Logo" width="200">
</p>
<p align="center">
<b>High-performance .NET 4.8 framework</b> for real-time Windows process monitoring, control, analysis, and <b>.NET managed code inspection</b>  including secure remote communication over TLS.
</p>

<p align="center">
Developed in <b>C# 7.3</b>  Targeting <b>.NET Framework 4.8</b>  GUI: <b>WinForms</b>
</p>

# NativeProcesses Framework

A modular, high-performance .NET framework for real-time monitoring, control, and in-depth analysis of Windows processes. It includes secure remote communication over TLS and advanced inspection capabilities for managed .NET applications.

Developed in **C# 7.3**, targeting **.NET Framework 4.8**, with **WinForms** used for demonstration simplicity.

-----

## Introduction

**NativeProcesses** is a high-performance, event-driven alternative to the standard `System.Diagnostics.Process` class. It bypasses the overhead and limitations of WMI and standard APIs by directly invoking low-level Windows system calls (P/Invoke). The framework uses `ntdll.dll`, `kernel32.dll`, `advapi32.dll`, and **Event Tracing for Windows (ETW)** to collect precise, real-time information about processes, threads, CPU, I/O, and security.

A key differentiator is its integration of **Microsoft.Diagnostics.Runtime (ClrMD)**, allowing it to perform deep, live-process inspection of other .NET applications' GC heaps, threads, and AppDomains without pausing the target.

In addition to local process management, it provides a **secure TCP/TLS 1.2-based network abstraction** that allows remote process viewing and control.

## Why NativeProcesses is Different

Most .NET process libraries rely on `System.Diagnostics.Process` or WMI, which are limited in detail and performance. **NativeProcesses** takes a different approach by communicating directly with the Windows kernel and runtime.

This enables:

 * **Real-time Process Metrics** with Task Manager-level speed.
 * **Deep .NET Inspection:** Live analysis of .NET GC heaps, exceptions, locks, and stacks via ClrMD.
 * **Advanced Native Enumeration:** Lists modules via PEB-walking, enumerates process handles, and maps virtual memory regions.
 * **Rich Contextual Data:** Gathers UWP package info, DPI awareness, security mitigations (DEP, ASLR), and extended thread priorities (I/O, Memory).
 * **Full Process Control:** Suspend, resume, kill, and set priority for processes and individual threads.
 * **Event-Driven Updates:** Optional ETW support for instant process start/stop notifications.
 * **Optimized Remote Access:** A secure TLS 1.2 server that broadcasts lightweight, volatile data packets to reduce network traffic.

**In short:** NativeProcesses provides a complete, high-performance foundation for building advanced diagnostic and monitoring tools, combining low-level native access with high-level managed code inspection.

-----

## Architecture Overview

```

 Application Layer (WinForms, Services) 
 e.g. ProcessInfoViewModel, RemoteClient 

 
 IProcessNotifier

 ProcessService (Central Hub) 
 Aggregates, caches, raises events, 
 manages async detail-loading queue 

 
 IProcessEventProvider

 Provider Layer (Pluggable) 
 Polling, ETW, WMI, Hybrid providers 

 

 Low-Level Access  Inspection Layer 
   
  Native (PInvoke)   Managed (ClrMD)  
  ManagedProcess   DotNetInspector  
  NativeLister    
  HandleLister    
  PebEnumerator    
   

 
 Windows Kernel APIs  .NET Runtime
```

-----

##  Core Layer - `NativeProcesses.Core`

### ProcessService

**Purpose:** The central class consumed by applications. It acts as the hub and faade for process information management.

**Responsibilities:**

1. Subscribes to a provider implementing `IProcessEventProvider` (e.g., `PollingProcessProvider`).
2. Maintains an in-memory cache (`ConcurrentDictionary<int, FullProcessInfo>`).
3. Exposes clean, thread-safe events: `ProcessAdded`, `ProcessRemoved`, `ProcessUpdated`.
4. **Asynchronous Detail Loading:** Manages a producer-consumer queue (`BlockingCollection`) to load "slow" details (ExePath, CommandLine, Signatures, .NET version) on background threads. This prevents ThreadPool starvation and keeps the UI responsive.
5. Smooths CPU usage data via an exponential moving average (EMA) for a more stable UI display.

-----

###  Provider System

Providers deliver raw process data from different sources and can be freely swapped or combined.

#### `PollingProcessProvider`

 * Periodically queries all processes using `NtQuerySystemInformation` from `ntdll.dll`.
 * Computes CPU usage precisely by comparing cumulative `KernelTime` and `UserTime` between snapshots.
 * Provides memory, thread, and I/O counters.
 * This is the primary provider used in the demos.

#### `EtwProcessProvider`

 * Subscribes to **Event Tracing for Windows (ETW)** kernel events: `Kernel.ProcessStart`, `Kernel.ProcessStop`, `Kernel.DiskIORead`, and `Kernel.DiskIOWrite`.
 * Delivers real-time, low-overhead notifications.

#### `WmiProcessProvider`

 * Uses WMI `__InstanceCreationEvent` and `__InstanceDeletionEvent`.
 * Higher overhead; serves as a fallback.

#### `HybridProcessProvider`

 * A simple wrapper to combine multiple providers (e.g., ETW for start/stop events and Polling for metric updates).

-----

###  Low-Level Access (Native  Managed)

This layer is composed of static classes and helpers that perform the actual data retrieval.

#### `Native (P/Invoke)` Layer (`NativeProcesses.Core.Native`)

 * **`NativeProcessLister`:** Enumerates all processes and threads using `NtQuerySystemInformation(SystemProcessInformation)`.
 * **`ManagedProcess`:** Encapsulates a process handle (`IntPtr`) for deep inspection.

| `ManagedProcess` Method | Description | API/Technique |
| :--- | :--- | :--- |
| `Kill()`, `Suspend()`, `Resume()` | Process control | `TerminateProcess`, `NtSuspendProcess` |
| `SetPriority()`, `GetPriority()` | Process priority | `SetPriorityClass` |
| `GetExePath()` | Reads the full executable path | `QueryFullProcessImageName` |
| `GetCommandLine()` | Reads the command line from the target's Process Environment Block (PEB) | `ReadProcessMemory` |
| `GetSecurityInfo()` | Gets user, integrity level, UAC elevation, and architecture (Wow64) | `OpenProcessToken`, `GetTokenInformation` |
| `GetMitigationInfo()` | Retrieves security mitigations (DEP, ASLR, CFG) | `GetProcessMitigationPolicy` |
| `GetIoCounters()` | Fetches I/O counters (Read/Write/Other ops and bytes) | `NtQueryInformationProcess` |
| `GetLoadedModules()` | Lists all modules by walking the PEB's LDR list | `PebModuleEnumerator` |
| `GetOpenHandles()` | Lists all open handles (files, threads, etc.) for the process | `NativeHandleLister` (`NtDuplicateObject`) |
| `GetVirtualMemoryRegions()` | Enumerates all virtual memory regions (Commit, Reserve, Free) | `NtQueryVirtualMemory` |
| `GetExtendedStatusFlags()` | Checks for attached debugger, Eco Mode, and Job membership | `NtQueryInformationProcess` |
| `GetDpiAndUIContextInfo()` | Determines DPI awareness and Immersive/UWP context | `GetProcessDpiAwareness` |
| `GetPackageFullName()` | Retrieves the UWP/MSIX package name, if any | `GetPackageFullNameFromProcess` |

 * **`ManagedThread`:** Encapsulates a thread handle (`IntPtr`) for thread-specific control.

 * **`GetExtendedPriorities()`**: Retrieves the thread's distinct **I/O Priority** and **Memory Priority**.

 * **`NetworkManager`:** Lists system-wide TCP and UDP connections and maps them to their owning PIDs using `GetExtendedTcpTable` and `GetExtendedUdpTable`.

 * **`WindowManager`:** Enumerates all top-level windows (visible and hidden) belonging to a specific process ID using `EnumWindows`.

#### `Managed (ClrMD)` Layer (`NativeProcesses.Core.Inspection`)

 * **`DotNetInspector`:** This static class uses **Microsoft.Diagnostics.Runtime (ClrMD)** to attach to running .NET processes non-invasively and inspect their managed state.

| `DotNetInspector` Method | Description |
| :--- | :--- |
| **`GetHeapStats`** | Lists all object types on the GC heap with their count and total size. |
| **`GetHeapExceptions`** | Finds all exception objects currently residing on the heap. |
| **`GetGcRoots`** | Analyzes object retention paths to help diagnose memory leaks. |
| **`GetGcRootPath`** | Traces a specific object's address back to its GC root. |
| **`GetManagedStack`** | Dumps the managed call stack for a specific thread. |
| **`GetLockingInfo`** | Identifies contended Monitor locks (`lock { ... }`) and potential deadlocks. |
| **`GetFinalizerInfo`** | Lists all objects in the finalizer queue, awaiting disposal. |
| **`GetThreadPoolInfo`** | Dumps the state of the .NET ThreadPool (worker/IO threads, CPU util). |
| **`GetStringDuplicateStats`** | Finds duplicate strings on the heap, identifying wasted memory. |
| **`GetAppDomainInfo`** | Lists all AppDomains and the assemblies loaded within them. |

-----

##  Network Layer - `NativeProcesses.Network`

### SecureTcpServer

 * Uses `TcpListener` with `SslStream` for encrypted TLS 1.2 connections (requires a `.pfx` certificate).
 * Authenticates clients using a secure, constant-time comparison of a pre-shared token.
 * Messages are serialized as JSON (Newtonsoft.Json) and compressed using `DeflateStream`.
 * Manages clients in a thread-safe list and provides a `BroadcastAsync` method.

### SecureTcpClient

 * Connects securely using `SslStream`.
 * **Implements Certificate Pinning:** The client validates the server's identity by comparing its certificate thumbprint against a local `server.cer` file, preventing MITM attacks.
 * Authenticates using the pre-shared token.
 * Receives live process updates and sends commands (e.g., `kill`, `get_all_processes`, `get_thread_priorities`).

### ProcessNetworkHost

The server-side bridge connecting the `ProcessService` to network clients.

1. Subscribes to `ProcessService` events (`ProcessAdded`, `ProcessUpdated`, `ProcessRemoved`).
2. **Optimized Broadcasting:** For `ProcessUpdated` events, it broadcasts a lightweight **`ProcessVolatileUpdate`** object containing only high-frequency metrics (CPU, Memory, I/O) to minimize network traffic.
3. Sends the full `FullProcessInfo` object only when a process is added (`OnProcessAdded`) or when a client requests the full list (`get_all_processes`).
4. Handles incoming client commands (like `kill`, `suspend`) and new requests (like `get_thread_priorities`) and executes them via the `ProcessManager`.

-----

##  Example Applications

### 1. Local Process Viewer (`UILocal`)

A feature-rich WinForms demo application showcasing the framework's local capabilities.

**Features:**

 * Live grid of all processes (Name, PID, User, CPU, Memory, I/O, .NET Version, etc.).
 * Secondary grid showing threads for the selected process.
 * Dynamic thread start-address resolution (e.g., `ntdll.dll+0x...`).
 * Dark title bar and modern styling.
 * **Extensive Diagnostics (Context Menu  F-Keys):**
 * `F3`: Show UWP/MSIX Package Info (if applicable).
 * `F4`: Show Process Windows (Visible  Hidden).
 * `F5`: Show Loaded Modules (DLLs).
 * `F6`: Show Open Handles (requires Admin).
 * `F7`: Show extended Thread I/O  Memory Priorities.
 * `F8`: Manually resolve thread start address.
 * `F9`: Show Virtual Memory Regions.
 * `F10`: Show .NET Heap Stats (ClrMD).
 * `F11`: Show .NET Exceptions on Heap (ClrMD).
 * `F12`: Show .NET GC Roots (ClrMD).
 * ...and menu items for .NET Locks, Finalizer Queue, ThreadPool, and more.
 * **System-Wide Network Monitor:** A button to open a new form showing all system TCP/UDP connections and their owning processes.

### 2. Remote Process Server (`Server`)

A console app that hosts the `ProcessService` and `SecureTcpServer`, waiting for client connections.

```csharp
// Load certificate and set port/token
var cert = new X509Certificate2("cert.pfx", "password");
var logger = new ConsoleLogger();
var service = new ProcessService(provider, logger);

// Set which details to load (can be changed live)
service.DetailOptions.LoadSignatureInfo = true;
service.DetailOptions.LoadMitigationInfo = true;

// Setup and start the server
var server = new SecureTcpServer(port, cert, "MySecretToken", logger);
var hostInstance = new ProcessNetworkHost(service, server, provider);

service.Start();
_ = server.StartAsync(); // Run server in background
Console.ReadLine(); // Wait for exit
hostInstance.ShutdownServer();
```

### 3. Remote Process Viewer (`RemoteClient`)

A WinForms client that connects to the `Server`, displays the process list in real-time, and allows remote control (Kill, Suspend, Resume, Get Thread Priorities).

```csharp
var client = new SecureTcpClient("127.0.0.1", 8888, "MySecretToken");
client.MessageReceived += Client_MessageReceived;
client.Disconnected += Client_Disconnected;

if (await client.ConnectAsync())
{
 // Request the full process list on connect
 await client.SendMessageAsync("get_all_processes", null);
}
```

-----

###  Network Security  Certificate Validation

The `SecureTcpClient` implements **Certificate Pinning** by default to prevent Man-in-the-Middle (MITM) attacks. It works by:

1. Loading a public `.cer` file (`server.cer`) from its local directory. This file must be the public key of the server's certificate, exported *without* the private key.
2. During the TSL handshake, it uses a `CustomCertificateValidationCallback`.
3. It compares the **thumbprint** of the certificate presented by the server with the thumbprint of the local `server.cer` file.
4. The connection is only allowed if the thumbprints match, ensuring the client is talking to the intended, trusted server.

-----

##  Technical Details

| Component | Technology |
| :--- | :--- |
| Language | C# 7.3 |
| Framework | .NET Framework 4.8 |
| GUI | WinForms |
| Network | TCP/TLS 1.2 + Deflate + JSON (Newtonsoft) |
| Architecture | Provider-based, Asynchronous, Thread-Safe |
| OS Compatibility | Windows 10/11 (x64) |

-----

##  Dependencies

The `NativeProcesses.Core` library itself is lightweight. Only the optional extensions and UI layers require external packages.

| Dependency | Purpose | Required For |
| :--- | :--- | :--- |
| **Newtonsoft.Json** | JSON serialization | `NativeProcesses.Network` |
| **Microsoft.Diagnostics.Tracing.TraceEvent** | ETW kernel event tracing | `EtwProcessProvider` (Optional) |
| **Microsoft.Diagnostics.Runtime (ClrMD)** | .NET managed code inspection | `DotNetInspector` (Optional) |
| **Microsoft.Windows.SDK.Contracts** | WinRT APIs for UWP info | `UwpManager` (Demo) |

Install required NuGet packages for the full feature set:

```bash
Install-Package Newtonsoft.Json
Install-Package Microsoft.Diagnostics.Tracing.TraceEvent
Install-Package Microsoft.Diagnostics.Runtime
Install-Package Microsoft.Windows.SDK.Contracts
```

-----

##  Repository Layout

```
NativeProcesses.Core/
 Engine/ # ProcessService, IProcessNotifier, IEngineLogger
 Inspection/ # DotNetInspector.cs (ClrMD)
 Models/ # FullProcessInfo, ThreadInfo, DotNetHeapStat, etc.
 Native/ # ManagedProcess.cs, ManagedThread.cs, NativeHandleLister.cs
  PebModuleEnumerator.cs, PsApiModuleEnumerator.cs, NetworkManager.cs
  WindowManager.cs, SignatureVerifier.cs, NativeProcessLister.cs
 Providers/ # PollingProcessProvider.cs, EtwProcessProvider.cs, etc.
 
NativeProcesses.Network/
 SecureTcpServer.cs
 SecureTcpClient.cs
 ProcessNetworkHost.cs
 ProcessVolatileUpdate.cs

UI/
 UILocal/ # Local WinForms Demo
  MainForm.cs, DetailForm.cs, ProcessInfoViewModel.cs, UwpManager.cs
 RemoteClient/ # Remote WinForms Client Demo
  MainForm.cs, ProcessInfoViewModel.cs
 Server/ # Remote Console Server Host
  Program.cs
```

-----

##  Quickstart

### Local Demo (`UILocal`)

1. Ensure you are on Windows 10/11 (x64).
2. Open the solution in Visual Studio 2019 or newer.
3. Set **`UILocal`** as the startup project.
4. **Run Visual Studio as Administrator** (required for inspecting system processes, enumerating handles, and ClrMD attachment).
5. Build and Run (F5).
6. Right-click processes or use F-keys (F3-F12) to explore diagnostic features.

### Remote Demo

1. **Generate Certificates:** Follow the steps below to create `cert.pfx` and `server.cer`.
2. **Run the Server:**
 * Place `cert.pfx` in the `UI/Server/bin/Debug/` folder.
 * Set **`Server`** as the startup project.
 * **Run as Administrator**.
3. **Run the Client:**
 * Place `server.cer` in the `UI/RemoteClient/bin/Debug/` folder.
 * Set **`RemoteClient`** as the startup project (can run as a normal user).
 * Run the client and click "Connect".

#### 1. Create the Certificate (PowerShell)

Run **PowerShell as Administrator**:

```powershell
New-SelfSignedCertificate -DnsName "localhost" -CertStoreLocation "cert:CurrentUserMy" -FriendlyName "NativeProcessServerCert" -KeyUsage DigitalSignature, KeyEncipherment
```

*(You can replace `"localhost"` with your server's IP/DNS name if connecting across machines.)*

#### 2. Export the Certificates (certmgr.msc)

1. Press `Win + R`, type `certmgr.msc`, and press **Enter**.
2. Navigate to **Personal**  **Certificates**.
3. Find the certificate "NativeProcessServerCert" or "localhost".

**A. Export `.pfx` (for the Server):**

1. Right-click  **All Tasks**  **Export...**
2. Select **"Yes, export the private key"**.
3. Use the default export format (PFX).
4. Set a **password** (e.g., `password`, as used in the demo code).
5. Save as `cert.pfx` in your **`Server`** project's output directory.

**B. Export `.cer` (for the Client):**

1. Right-click again  **All Tasks**  **Export...**
2. Select **"No, do not export the private key"**.
3. Choose **"Base-64 encoded X.509 (.CER)"**.
4. Save as `server.cer` in your **`RemoteClient`** project's output directory.

-----

##  Project Status  Future Scope

This framework is stable and feature-complete for its .NET 4.8 target. The "Known Issues" from the previous version have been resolved.

 *  **Async Detail Loading:** Implemented with a dedicated producer-consumer queue to prevent ThreadPool starvation.
 *  **Log Denoising:** Repetitive "Access Denied" errors are now suppressed in the logger.
 *  **Network Optimization:** Server now broadcasts lightweight `ProcessVolatileUpdate` packets, dramatically reducing network traffic.

Future development would focus on modernization:

 * **.NET 8 Port:** Officially porting the library to modern .NET, which is largely compatible.
 * **WPF/MVVM Demo:** Creating a new demo UI to better showcase the framework's decoupled architecture.
 * **Expanded Remote API:** Adding endpoints to the remote server to expose the powerful `DotNetInspector` (ClrMD) features to remote clients.

-----

## License  Author

This project is licensed under the **GNU General Public License v3.0 (GPLv3)**.

You are free to use, modify, and distribute this software under the terms of the GPLv3. Any derivative work or redistributed version must also remain open-source under the same license.

For the full license text, see: [https://www.gnu.org/licenses/gpl-3.0.html](https://www.gnu.org/licenses/gpl-3.0.html)

-----

## Feedback

Contributions, code reviews, and performance reports are welcome.
The goal of **NativeProcesses** is to remain a **transparent, native, and efficient** Windows process management library for .NET developers.

-----

**Author:** Selahattin Erkoc
**Project:** NativeProcesses Framework
**Version:** 1.5.0 (2025)

-----

## Third-Party Notices

This project utilizes the following open-source libraries. Their original license terms and copyright notices are retained.

### Newtonsoft.Json

Copyright  James Newton-King
Licensed under the [MIT License](https://licenses.nuget.org/MIT)

### Microsoft.Diagnostics.Tracing.TraceEvent

Copyright  Microsoft Corporation
Licensed under the [MIT License](https://licenses.nuget.org/MIT)

### Microsoft.Diagnostics.Runtime (ClrMD)

Copyright  Microsoft Corporation
Licensed under the [MIT License](https://licenses.nuget.org/MIT)

### Microsoft.Windows.SDK.Contracts

Copyright  Microsoft Corporation
Licensed under the [MIT License](https://licenses.nuget.org/MIT)

-----

<p align="center">
 If you find this project useful, please consider giving it a star on GitHub!
</p>
/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
using Microsoft.Diagnostics.Runtime;
using NativeProcesses.Core.Models;
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;

namespace NativeProcesses.Core.Inspection
{
    public static class DotNetInspector
    {
        public static List<DotNetHeapStat> GetHeapStats(int pid)
        {
            DataTarget target = null;
            try
            {
                target = DataTarget.AttachToProcess(pid, false);

                if (target.ClrVersions == null || target.ClrVersions.Count() == 0)
                {
                    throw new Exception("This is not a managed .NET process, or ClrMD could not attach.");
                }

                ClrInfo runtimeInfo = target.ClrVersions[0];
                ClrRuntime runtime = runtimeInfo.CreateRuntime();
                ClrHeap heap = runtime.Heap;

                if (!heap.CanWalkHeap)
                {
                    throw new Exception("The .NET heap is not in a walkable state (e.g., currently in GC).");
                }

                var stats = new Dictionary<string, (int Count, long TotalSize)>();

                foreach (ClrObject obj in heap.EnumerateObjects())
                {
                    if (obj.Type == null) continue;

                    string typeName = obj.Type.Name;
                    if (stats.TryGetValue(typeName, out var stat))
                    {
                        stats[typeName] = (stat.Count + 1, stat.TotalSize + (long)obj.Size);
                    }
                    else
                    {
                        stats[typeName] = (1, (long)obj.Size);
                    }
                }

                return stats
                    .Select(kvp => new DotNetHeapStat
                    {
                        TypeName = kvp.Key,
                        Count = kvp.Value.Count,
                        TotalSize = kvp.Value.TotalSize
                    })
                    .OrderByDescending(s => s.TotalSize)
                    .ToList();
            }
            finally
            {
                target?.Dispose();
            }
        }
        public static List<DotNetExceptionInfo> GetHeapExceptions(int pid)
        {
            DataTarget target = null;
            var exceptions = new List<DotNetExceptionInfo>();

            try
            {
                target = DataTarget.AttachToProcess(pid, false);
                if (target.ClrVersions == null || target.ClrVersions.Count() == 0)
                {
                    throw new Exception("This is not a managed .NET process, or ClrMD could not attach.");
                }

                ClrRuntime runtime = target.ClrVersions[0].CreateRuntime();
                ClrHeap heap = runtime.Heap;

                if (!heap.CanWalkHeap)
                {
                    throw new Exception("The .NET heap is not in a walkable state (e.g., currently in GC).");
                }

                // ClrType exceptionType = heap.ExceptionType; // <-- Wird nicht mehr benötigt
                // if (exceptionType == null)
                // {
                //     throw new Exception("Could not find System.Exception type in the heap.");
                // }

                foreach (ClrObject obj in heap.EnumerateObjects())
                {
                    // ERSETZT: if (obj.Type == null || !obj.Type.IsAssignableTo(exceptionType))
                    // DURCH:
                    if (!obj.IsException)
                    {
                        continue;
                    }

                    string message = "N/A";
                    try
                    {
                        message = obj.ReadStringField("_message");
                    }
                    catch { }

                    int hResult = 0;
                    try
                    {
                        hResult = obj.ReadField<int>("_HResult");
                    }
                    catch { }

                    ulong innerAddress = 0;
                    try
                    {
                        innerAddress = obj.ReadObjectField("_innerException").Address;
                    }
                    catch { }

                    exceptions.Add(new DotNetExceptionInfo
                    {
                        Address = obj.Address,
                        TypeName = obj.Type.Name,
                        Message = message,
                        HResult = hResult,
                        InnerExceptionAddress = innerAddress
                    });
                }

                return exceptions;
            }
            finally
            {
                target?.Dispose();
            }
        }

        public static List<DotNetRootInfo> GetGcRoots(int pid)
        {
            DataTarget target = null;
            var rootResults = new List<DotNetRootInfo>();

            try
            {
                target = DataTarget.AttachToProcess(pid, false);
                if (target.ClrVersions == null || target.ClrVersions.Count() == 0)
                {
                    throw new Exception("This is not a managed .NET process, or ClrMD could not attach.");
                }

                ClrRuntime runtime = target.ClrVersions[0].CreateRuntime();
                ClrHeap heap = runtime.Heap;

                if (!heap.CanWalkHeap)
                {
                    throw new Exception("The .NET heap is not in a walkable state (e.g., currently in GC).");
                }

                foreach (var root in heap.EnumerateRoots())
                {
                    if (root.Object == 0 || root.Object.IsNull || root.Object.Type == null)
                    {
                        continue;
                    }

                    string rootName = "N/A";

                    if (root.RootKind == ClrRootKind.Stack)
                    {
                        if (root is ClrStackRoot stackRoot && stackRoot.StackFrame != null && stackRoot.StackFrame.Method != null)
                        {
                            rootName = $"Stack @ {stackRoot.StackFrame.Method.Name} (Thread {stackRoot.StackFrame.Thread.ManagedThreadId})";
                        }
                        else
                        {
                            rootName = "Stack (unmanaged?)";
                        }
                    }
                    else if (root.RootKind == ClrRootKind.FinalizerQueue)
                    {
                        rootName = "Finalizer Queue";
                    }
                    else if (root is ClrHandle handle)
                    {
                        rootName = $"Handle ({handle.HandleKind})";
                    }
                    else
                    {
                        rootName = root.RootKind.ToString();
                    }


                    var rootInfo = new DotNetRootInfo
                    {
                        RootType = root.RootKind.ToString(),
                        Address = root.Object.Address,
                        IsPinned = root.IsPinned,
                        Name = rootName
                    };

                    var stats = new Dictionary<string, (int Count, long TotalSize)>();
                    var objectQueue = new Queue<ClrObject>();
                    var visited = new HashSet<ulong>();

                    objectQueue.Enqueue(root.Object);
                    visited.Add(root.Object.Address);

                    while (objectQueue.Count > 0)
                    {
                        ClrObject obj = objectQueue.Dequeue();
                        if (obj.Type == null) continue;

                        string typeName = obj.Type.Name;
                        if (stats.TryGetValue(typeName, out var stat))
                        {
                            stats[typeName] = (stat.Count + 1, stat.TotalSize + (long)obj.Size);
                        }
                        else
                        {
                            stats[typeName] = (1, (long)obj.Size);
                        }

                        foreach (var innerRef in obj.EnumerateReferences(carefully: false, considerDependantHandles: true))
                        {
                            if (innerRef.IsNull || innerRef.IsFree) continue;

                            if (visited.Add(innerRef.Address))
                            {
                                objectQueue.Enqueue(innerRef);
                            }
                        }
                    }

                    rootInfo.ReferencedObjects = stats
                        .Select(kvp => new DotNetHeapStat
                        {
                            TypeName = kvp.Key,
                            Count = kvp.Value.Count,
                            TotalSize = kvp.Value.TotalSize
                        })
                        .OrderByDescending(s => s.TotalSize)
                        .ToList();

                    if (rootInfo.ReferencedObjects.Count > 0)
                    {
                        rootResults.Add(rootInfo);
                    }
                }

                return rootResults.OrderByDescending(r => r.ReferencedObjects.Sum(o => o.TotalSize)).ToList();
            }
            finally
            {
                target?.Dispose();
            }
        }

        public static List<DotNetStackFrame> GetManagedStack(int pid, int osThreadId)
        {
            DataTarget target = null;
            var frames = new List<DotNetStackFrame>();

            try
            {
                target = DataTarget.AttachToProcess(pid, false);
                if (target.ClrVersions == null || target.ClrVersions.Count() == 0)
                {
                    throw new Exception("This is not a managed .NET process, or ClrMD could not attach.");
                }

                ClrRuntime runtime = target.ClrVersions[0].CreateRuntime();

                ClrThread thread = runtime.Threads.FirstOrDefault(t => t.OSThreadId == (uint)osThreadId);

                if (thread == null)
                {
                    throw new Exception($"Could not find managed thread with OSThreadId {osThreadId}.");
                }

                if (thread.State.HasFlag(ClrThreadState.TS_Unstarted))
                {
                    frames.Add(new DotNetStackFrame { MethodName = "[Thread Unstarted]" });
                    return frames;
                }

                foreach (var frame in thread.EnumerateStackTrace())
                {
                    frames.Add(new DotNetStackFrame
                    {
                        MethodName = frame.Method?.ToString() ?? "[Unknown Method]",
                        InstructionPointer = frame.InstructionPointer,
                        StackPointer = frame.StackPointer
                    });
                }

                if (frames.Count == 0)
                {
                    frames.Add(new DotNetStackFrame { MethodName = "[Stack empty or in unmanaged code]" });
                }

                return frames;
            }
            finally
            {
                target?.Dispose();
            }
        }

        public static List<DotNetLockInfo> GetLockingInfo(int pid)
        {
            DataTarget target = null;
            var results = new List<DotNetLockInfo>();

            try
            {
                target = DataTarget.AttachToProcess(pid, false);
                if (target.ClrVersions == null || target.ClrVersions.Count() == 0)
                {
                    throw new Exception("This is not a managed .NET process, or ClrMD could not attach.");
                }

                ClrRuntime runtime = target.ClrVersions[0].CreateRuntime();
                ClrHeap heap = runtime.Heap;

                if (!heap.CanWalkHeap)
                {
                    throw new Exception("The .NET heap is not in a walkable state (e.g., currently in GC).");
                }

                var threads = runtime.Threads.ToDictionary(t => t.Address);

                foreach (SyncBlock sync in heap.EnumerateSyncBlocks())
                {
                    if (sync == null)
                    {
                        continue;
                    }

                    if (sync.IsMonitorHeld || sync.WaitingThreadCount > 0)
                    {
                        ClrObject obj = heap.GetObject(sync.Object);

                        var info = new DotNetLockInfo
                        {
                            LockAddress = obj.Address,
                            ObjectType = obj.Type?.Name ?? "[Unknown Type]"
                        };

                        if (sync.IsMonitorHeld && sync.HoldingThreadAddress != 0)
                        {
                            if (threads.TryGetValue(sync.HoldingThreadAddress, out ClrThread owner))
                            {
                                info.OwningThreadId = owner.ManagedThreadId;
                            }
                        }

                        info.WaitingThreadCount = sync.WaitingThreadCount;

                        results.Add(info);
                    }
                }

                return results;
            }
            finally
            {
                target?.Dispose();
            }
        }
        public static List<DotNetFinalizerInfo> GetFinalizerInfo(int pid)
        {
            DataTarget target = null;
            var results = new List<DotNetFinalizerInfo>();

            try
            {
                target = DataTarget.AttachToProcess(pid, false);
                if (target.ClrVersions == null || target.ClrVersions.Count() == 0)
                {
                    throw new Exception("This is not a managed .NET process, or ClrMD could not attach.");
                }

                ClrRuntime runtime = target.ClrVersions[0].CreateRuntime();
                ClrHeap heap = runtime.Heap;

                if (!heap.CanWalkHeap)
                {
                    throw new Exception("The .NET heap is not in a walkable state (e.g., currently in GC).");
                }

                foreach (ClrObject obj in heap.EnumerateFinalizableObjects())
                {
                    if (obj.IsNull || obj.Type == null)
                        continue;

                    results.Add(new DotNetFinalizerInfo
                    {
                        ObjectAddress = obj.Address,
                        TypeName = obj.Type.Name
                    });
                }

                return results;
            }
            finally
            {
                target?.Dispose();
            }
        }
        public static DotNetThreadPoolInfo GetThreadPoolInfo(int pid)
        {
            DataTarget target = null;
            try
            {
                target = DataTarget.AttachToProcess(pid, false);
                if (target.ClrVersions == null || target.ClrVersions.Count() == 0)
                {
                    throw new Exception("This is not a managed .NET process, or ClrMD could not attach.");
                }

                ClrRuntime runtime = target.ClrVersions[0].CreateRuntime();

                ClrThreadPool tp = runtime.ThreadPool;
                if (tp == null)
                {
                    throw new Exception("Could not retrieve ThreadPool information.");
                }

                DotNetThreadPoolInfo info = new DotNetThreadPoolInfo
                {
                    CpuUtilization = tp.CpuUtilization,
                    MinWorkerThreads = tp.MinThreads,
                    MaxWorkerThreads = tp.MaxThreads,
                    ActiveWorkerThreads = tp.ActiveWorkerThreads,
                    IdleWorkerThreads = tp.IdleWorkerThreads,
                    MinCompletionPortThreads = tp.MinCompletionPorts,
                    MaxCompletionPortThreads = tp.MaxCompletionPorts,
                    ActiveCompletionPortThreads = tp.TotalCompletionPorts - tp.FreeCompletionPorts,
                    IdleCompletionPortThreads = tp.FreeCompletionPorts
                };

                return info;
            }
            finally
            {
                target?.Dispose();
            }
        }
        public static List<DotNetGcRootPathInfo> GetGcRootPath(int pid, ulong targetObjectAddress)
        {
            DataTarget target = null;
            var results = new List<DotNetGcRootPathInfo>();

            try
            {
                target = DataTarget.AttachToProcess(pid, false);
                if (target.ClrVersions == null || target.ClrVersions.Count() == 0)
                {
                    throw new Exception("This is not a managed .NET process, or ClrMD could not attach.");
                }

                ClrRuntime runtime = target.ClrVersions[0].CreateRuntime();
                ClrHeap heap = runtime.Heap;

                if (!heap.CanWalkHeap)
                {
                    throw new Exception("The .NET heap is not in a walkable state (e.g., currently in GC).");
                }

                GCRoot gcRoot = new GCRoot(heap, new[] { targetObjectAddress });

                var path = gcRoot.EnumerateRootPaths().FirstOrDefault();

                if (path.Root == null)
                {
                    throw new Exception("Could not find a GC root path for the specified object.");
                }

                results.Add(new DotNetGcRootPathInfo
                {
                    Kind = "Root",
                    Address = path.Root.Object.Address,
                    TypeName = path.Root.Object.Type?.Name ?? "[Unknown Type]",
                    RootKind = path.Root.RootKind.ToString()
                });

                var link = path.Path;
                while (link != null)
                {
                    if (link.Object == path.Root.Object.Address)
                    {
                        link = link.Next;
                        continue;
                    }

                    ClrObject obj = heap.GetObject(link.Object);
                    results.Add(new DotNetGcRootPathInfo
                    {
                        Kind = "Reference",
                        Address = obj.Address,
                        TypeName = obj.Type?.Name ?? "[Unknown Type]",
                        RootKind = string.Empty
                    });

                    link = link.Next;
                }

                return results;
            }
            finally
            {
                target?.Dispose();
            }
        }
        public static List<DotNetStringDuplicateInfo> GetStringDuplicateStats(int pid)
        {
            DataTarget target = null;
            var stringStats = new Dictionary<string, (int Count, long TotalSize)>();

            try
            {
                target = DataTarget.AttachToProcess(pid, false);
                if (target.ClrVersions == null || target.ClrVersions.Count() == 0)
                {
                    throw new Exception("This is not a managed .NET process, or ClrMD could not attach.");
                }

                ClrRuntime runtime = target.ClrVersions[0].CreateRuntime();
                ClrHeap heap = runtime.Heap;

                if (!heap.CanWalkHeap)
                {
                    throw new Exception("The .NET heap is not in a walkable state (e.g., currently in GC).");
                }

                if (heap.StringType == null)
                {
                    throw new Exception("Could not find System.String type in the heap.");
                }

                foreach (ClrObject obj in heap.EnumerateObjects())
                {
                    if (obj.Type != heap.StringType || obj.IsNull)
                        continue;

                    string value;
                    try
                    {
                        value = obj.AsString(1024);
                    }
                    catch
                    {
                        continue;
                    }

                    if (value == null)
                        continue;

                    if (stringStats.TryGetValue(value, out var stat))
                    {
                        stringStats[value] = (stat.Count + 1, stat.TotalSize + (long)obj.Size);
                    }
                    else
                    {
                        stringStats[value] = (1, (long)obj.Size);
                    }
                }

                return stringStats
                    .Where(kvp => kvp.Value.Count > 1)
                    .Select(kvp => new DotNetStringDuplicateInfo
                    {
                        Value = kvp.Key,
                        Count = kvp.Value.Count,
                        TotalSize = kvp.Value.TotalSize
                    })
                    .OrderByDescending(s => s.WastedSize)
                    .ToList();
            }
            finally
            {
                target?.Dispose();
            }
        }
        public static List<DotNetStringDuplicateInfo> GetAllHeapStrings(int pid)
        {
            DataTarget target = null;
            var stringStats = new Dictionary<string, (int Count, long TotalSize)>();

            try
            {
                target = DataTarget.AttachToProcess(pid, false);
                if (target.ClrVersions == null || target.ClrVersions.Count() == 0)
                {
                    throw new Exception("This is not a managed .NET process, or ClrMD could not attach.");
                }

                ClrRuntime runtime = target.ClrVersions[0].CreateRuntime();
                ClrHeap heap = runtime.Heap;

                if (!heap.CanWalkHeap)
                {
                    throw new Exception("The .NET heap is not in a walkable state (e.g., currently in GC).");
                }

                if (heap.StringType == null)
                {
                    throw new Exception("Could not find System.String type in the heap.");
                }

                foreach (ClrObject obj in heap.EnumerateObjects())
                {
                    if (obj.Type != heap.StringType || obj.IsNull)
                        continue;

                    string value;
                    try
                    {
                        value = obj.AsString(1024);
                    }
                    catch
                    {
                        continue;
                    }

                    if (value == null)
                        continue;

                    if (stringStats.TryGetValue(value, out var stat))
                    {
                        stringStats[value] = (stat.Count + 1, stat.TotalSize + (long)obj.Size);
                    }
                    else
                    {
                        stringStats[value] = (1, (long)obj.Size);
                    }
                }

                return stringStats
                    .Select(kvp => new DotNetStringDuplicateInfo
                    {
                        Value = kvp.Key,
                        Count = kvp.Value.Count,
                        TotalSize = kvp.Value.TotalSize
                    })
                    .OrderByDescending(s => s.WastedSize)
                    .ToList();
            }
            finally
            {
                target?.Dispose();
            }
        }
        public static List<DotNetAppDomainInfo> GetAppDomainInfo(int pid)
        {
            DataTarget target = null;
            var results = new List<DotNetAppDomainInfo>();

            try
            {
                target = DataTarget.AttachToProcess(pid, false);
                if (target.ClrVersions == null || target.ClrVersions.Count() == 0)
                {
                    throw new Exception("This is not a managed .NET process, or ClrMD could not attach.");
                }

                ClrRuntime runtime = target.ClrVersions[0].CreateRuntime();

                foreach (ClrAppDomain appDomain in runtime.AppDomains)
                {
                    var domainInfo = new DotNetAppDomainInfo
                    {
                        Id = appDomain.Id,
                        Name = appDomain.Name,
                        Address = appDomain.Address,
                        ConfigFile = appDomain.ConfigurationFile,
                        ApplicationBase = appDomain.ApplicationBase
                    };

                    foreach (ClrModule module in appDomain.Modules)
                    {
                        domainInfo.LoadedAssemblies.Add(module.AssemblyName ?? module.Name);
                    }

                    results.Add(domainInfo);
                }

                if (runtime.SystemDomain != null)
                {
                    var systemDomain = new DotNetAppDomainInfo
                    {
                        Id = runtime.SystemDomain.Id,
                        Name = runtime.SystemDomain.Name,
                        Address = runtime.SystemDomain.Address
                    };
                    foreach (ClrModule module in runtime.SystemDomain.Modules)
                    {
                        systemDomain.LoadedAssemblies.Add(module.AssemblyName ?? module.Name);
                    }
                    results.Add(systemDomain);
                }

                if (runtime.SharedDomain != null)
                {
                    var sharedDomain = new DotNetAppDomainInfo
                    {
                        Id = runtime.SharedDomain.Id,
                        Name = runtime.SharedDomain.Name,
                        Address = runtime.SharedDomain.Address
                    };
                    foreach (ClrModule module in runtime.SharedDomain.Modules)
                    {
                        sharedDomain.LoadedAssemblies.Add(module.AssemblyName ?? module.Name);
                    }
                    results.Add(sharedDomain);
                }

                return results;
            }
            finally
            {
                target?.Dispose();
            }
        }
    }
}
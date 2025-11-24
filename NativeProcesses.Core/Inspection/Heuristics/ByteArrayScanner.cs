/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
using Microsoft.Diagnostics.Runtime;
using System;
using System.Collections.Generic;

namespace NativeProcesses.Core.Inspection.Heuristics
{
    public class ByteArrayScanner
    {
        public IEnumerable<HeuristicResult> Scan(ClrHeap heap)
        {
            var results = new List<HeuristicResult>();
            int pointerSize = heap.Runtime.DataTarget.DataReader.PointerSize;

            foreach (var obj in heap.EnumerateObjects())
            {
                if (obj.Type == null || !obj.IsArray || obj.Type.ElementType != ClrElementType.UInt8)
                    continue;

                int length = obj.AsArray().Length;

                if (length < 4096) continue;

                ulong dataOffset = (ulong)pointerSize + 4;
                ulong dataAddress = obj.Address + dataOffset;

                byte[] buffer = new byte[Math.Min(length, 8192)];
                int bytesRead = heap.Runtime.DataTarget.DataReader.Read(dataAddress, new Span<byte>(buffer));

                if (bytesRead > 2)
                {
                    if (buffer[0] == 0x4D && buffer[1] == 0x5A)
                    {
                        results.Add(new HeuristicResult(
                            "Floating PE Header",
                            ScanCategory.CodeInjection,
                            ThreatScore.Critical,
                            $"Found a raw PE file (DLL/EXE) in a byte[] array. Size: {length:N0} bytes.",
                            obj.Address.ToString("X"),
                            "MZ Header"
                        ));
                        continue;
                    }

                    double entropy = EntropyCalculator.Calculate(buffer, bytesRead);
                    if (entropy > 7.2)
                    {
                        results.Add(new HeuristicResult(
                            "High Entropy Blob",
                            ScanCategory.Obfuscation,
                            ThreatScore.High,
                            $"Encrypted or packed payload detected. Entropy: {entropy:F2}. Size: {length:N0}",
                            obj.Address.ToString("X"),
                            $"Entropy: {entropy:F2}"
                        ));
                    }
                }
            }
            return results;
        }
    }
}
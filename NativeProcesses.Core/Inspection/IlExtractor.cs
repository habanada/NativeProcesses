/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
using Microsoft.Diagnostics.Runtime;
using System;

namespace NativeProcesses.Core.Inspection
{
    public static class IlExtractor
    {
        public static byte[] GetMethodIL(ClrMethod method)
        {
            if (method == null) return new byte[0];

            ILInfo ilInfo = method.GetILInfo();

            if (ilInfo == null) return new byte[0];

            ulong ilAddr = ilInfo.Address;
            int ilLen = ilInfo.Length;

            if (ilAddr == 0 || ilLen <= 0) return new byte[0];

            byte[] buffer = new byte[ilLen];
            int read = method.Type.Heap.Runtime.DataTarget.DataReader.Read(ilAddr, new Span<byte>(buffer));

            if (read != ilLen)
            {
                return new byte[0];
            }

            return buffer;
        }

        public static string FormatIlAsHex(byte[] il)
        {
            if (il == null || il.Length == 0) return "No IL Code";
            return BitConverter.ToString(il).Replace("-", " ");
        }
    }
}
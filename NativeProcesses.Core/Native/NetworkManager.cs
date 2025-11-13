using NativeProcesses.Core.Models;
using System;
using System.Collections.Generic;
using System.Net;
using System.Runtime.InteropServices;

namespace NativeProcesses.Core.Native
{
    public static class NetworkManager
    {
        private static readonly Dictionary<uint, string> TcpStates = new Dictionary<uint, string>
        {
            { 1, "CLOSED" },
            { 2, "LISTENING" },
            { 3, "SYN-SENT" },
            { 4, "SYN-RECEIVED" },
            { 5, "ESTABLISHED" },
            { 6, "FIN-WAIT-1" },
            { 7, "FIN-WAIT-2" },
            { 8, "CLOSE-WAIT" },
            { 9, "CLOSING" },
            { 10, "LAST-ACK" },
            { 11, "TIME-WAIT" },
            { 12, "DELETE-TCB" }
        };

        public static List<NetworkConnectionInfo> GetNetworkConnections()
        {
            var connections = new List<NetworkConnectionInfo>();
            connections.AddRange(GetConnections<IpHelper.MIB_TCPTABLE_OWNER_PID, IpHelper.MIB_TCPROW_OWNER_PID>(IpHelper.AF_INET, (int)IpHelper.TCP_TABLE_CLASS.TCP_TABLE_OWNER_PID_ALL, IpHelper.GetExtendedTcpTable));
            connections.AddRange(GetConnections<IpHelper.MIB_UDPTABLE_OWNER_PID, IpHelper.MIB_UDPROW_OWNER_PID>(IpHelper.AF_INET, (int)IpHelper.UDP_TABLE_CLASS.UDP_TABLE_OWNER_PID, IpHelper.GetExtendedUdpTable));
            return connections;
        }

        private delegate uint GetTableDelegate(IntPtr pTable, ref int pdwSize, bool bOrder, int ulAf, int TableClass, uint Reserved);
        private static List<NetworkConnectionInfo> GetConnections<TTable, TRow>(int af, int tableClass, GetTableDelegate getTable)
            where TTable : struct
            where TRow : struct
        {
            var connections = new List<NetworkConnectionInfo>();
            IntPtr buffer = IntPtr.Zero;
            int bufferSize = 0;

            uint result = getTable(IntPtr.Zero, ref bufferSize, true, af, tableClass, 0);

            try
            {
                while (result == 122)
                {
                    if (buffer != IntPtr.Zero)
                        Marshal.FreeHGlobal(buffer);

                    buffer = Marshal.AllocHGlobal(bufferSize);
                    result = getTable(buffer, ref bufferSize, true, af, tableClass, 0);
                }

                if (result != 0)
                    return connections;

                int rowSize = Marshal.SizeOf(typeof(TRow));
                uint numEntries = (uint)Marshal.ReadInt32(buffer);
                IntPtr rowPtr = (IntPtr)((long)buffer + sizeof(uint));

                for (int i = 0; i < numEntries; i++)
                {
                    object rowObj = Marshal.PtrToStructure(rowPtr, typeof(TRow));
                    connections.Add(ParseRow(rowObj));
                    rowPtr = (IntPtr)((long)rowPtr + rowSize);
                }
            }
            finally
            {
                if (buffer != IntPtr.Zero)
                    Marshal.FreeHGlobal(buffer);
            }

            return connections;
        }

        private static NetworkConnectionInfo ParseRow(object row)
        {
            if (row is IpHelper.MIB_TCPROW_OWNER_PID tcpRow)
            {
                return new NetworkConnectionInfo
                {
                    Protocol = "TCP",
                    LocalAddress = new IPAddress(tcpRow.localAddr).ToString(),
                    LocalPort = (ushort)IPAddress.NetworkToHostOrder((short)tcpRow.localPort),
                    RemoteAddress = new IPAddress(tcpRow.remoteAddr).ToString(),
                    RemotePort = (ushort)IPAddress.NetworkToHostOrder((short)tcpRow.remotePort),
                    State = TcpStates.ContainsKey(tcpRow.state) ? TcpStates[tcpRow.state] : tcpRow.state.ToString(),
                    OwnerPid = (int)tcpRow.owningPid
                };
            }

            if (row is IpHelper.MIB_UDPROW_OWNER_PID udpRow)
            {
                return new NetworkConnectionInfo
                {
                    Protocol = "UDP",
                    LocalAddress = new IPAddress(udpRow.localAddr).ToString(),
                    LocalPort = (ushort)IPAddress.NetworkToHostOrder((short)udpRow.localPort),
                    RemoteAddress = "0.0.0.0",
                    RemotePort = 0,
                    State = string.Empty,
                    OwnerPid = (int)udpRow.owningPid
                };
            }

            return null;
        }
    }
}
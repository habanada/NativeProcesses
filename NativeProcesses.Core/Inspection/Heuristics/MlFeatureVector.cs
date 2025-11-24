/*
   NativeProcesses Framework  |  © 2025 Selahattin Erkoc
   Licensed under GNU GPL v3  |  https://www.gnu.org/licenses/
*/
namespace NativeProcesses.Core.Inspection.Heuristics
{
    public struct MlFeatureVector
    {
        public float AvgEntropy;
        public float MaxEntropy;
        public int PinnedObjectCount;
        public int CryptoObjectCount;
        public int ExecutableMemoryRegions;
        public int SuspiciousStringCount;
        public int FloatingAssemblyCount;
        public int DynamicMethodCount;
        public int FinalizerQueueSize;
        public int UnsafeIlCount; // Neu hinzugefügt für den IL Scanner

        public float[] ToArray()
        {
            return new float[]
            {
                AvgEntropy,
                MaxEntropy,
                (float)PinnedObjectCount,
                (float)CryptoObjectCount,
                (float)ExecutableMemoryRegions,
                (float)SuspiciousStringCount,
                (float)FloatingAssemblyCount,
                (float)DynamicMethodCount,
                (float)FinalizerQueueSize,
                (float)UnsafeIlCount
            };
        }
    }
}
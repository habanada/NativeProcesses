namespace NativeProcesses.Core.Native
{
    internal static class NativeDefinitions
    {
        public static class SystemInformationClass
        {
            public const int SystemProcessInformation = 5;
            public const int SystemHandleInformation = 16;
            public const int SystemThreadInformation = 51;
            public const int SystemExtendedHandleInformation = 64;
            public const int SystemBootEntropyInformation = 0x75;
        }

        public static class ProcessInformationClass
        {
            public const int ProcessBasicInformation = 0;
            public const int ProcessIoCounters = 4;
            public const int ProcessWow64Information = 26;
            public const int ProcessBreakOnTermination = 29;
            public const int ProcessDebugObjectHandle = 30;
            public const int ProcessIoPriority = 34;
            public const int ProcessPowerThrottlingState = 45;
        }

        public static class ThreadInformationClass
        {
            public const int ThreadIoPriority = 33;
            public const int ThreadPagePriority = 39;
        }

        public static class GdiObjectType
        {
            public const int GDI_OBJECT_TYPE_REGION = 0x04;
            public const int GDI_OBJECT_TYPE_BITMAP = 0x05;
            public const int GDI_OBJECT_TYPE_FONT = 0x0A;
            public const int GDI_OBJECT_TYPE_BRUSH = 0x10;
            public const int GDI_OBJECT_TYPE_PEN = 0x30;
        }

        public static class UserObjectType
        {
            public const int otWindow = 1;
            public const int otMenu = 2;
            public const int otCursorIcon = 3;
        }
    }
}
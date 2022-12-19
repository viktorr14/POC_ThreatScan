using System;
using System.Runtime.InteropServices;

namespace AMSI_DLL_TEST.Antivirus
{
    internal static class Amsi
    {
        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("Amsi.dll", EntryPoint = "AmsiInitialize", CallingConvention = CallingConvention.StdCall)]
        internal static extern int Initialize([MarshalAs(UnmanagedType.LPWStr)] string appName, out IntPtr context);

        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("Amsi.dll", EntryPoint = "AmsiUninitialize", CallingConvention = CallingConvention.StdCall)]
        internal static extern void Uninitialize(IntPtr context);

        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("Amsi.dll", EntryPoint = "AmsiOpenSession", CallingConvention = CallingConvention.StdCall)]
        internal static extern int OpenSession(IntPtr context, out IntPtr session);

        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("Amsi.dll", EntryPoint = "AmsiCloseSession", CallingConvention = CallingConvention.StdCall)]
        internal static extern void CloseSession(IntPtr context, IntPtr session);

        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("Amsi.dll", EntryPoint = "AmsiScanString", CallingConvention = CallingConvention.StdCall)]
        internal static extern int ScanString(IntPtr context, [In, MarshalAs(UnmanagedType.LPWStr)] string content, [In, MarshalAs(UnmanagedType.LPWStr)] string contentName, IntPtr session, out AmsiResult result);

        [DefaultDllImportSearchPaths(DllImportSearchPath.System32)]
        [DllImport("Amsi.dll", EntryPoint = "AmsiScanBuffer", CallingConvention = CallingConvention.StdCall)]
        internal static extern int ScanBuffer(IntPtr context, byte[] buffer, uint length, string contentName, IntPtr session, out AmsiResult result);

        internal static bool ResultIsMalware(AmsiResult result) => result >= AmsiResult.AMSI_RESULT_DETECTED;
    }

    internal enum AmsiResult
    {
        AMSI_RESULT_CLEAN = 0,
        AMSI_RESULT_NOT_DETECTED = 1,
        AMSI_RESULT_BLOCKED_BY_ADMIN_START = 16384,
        AMSI_RESULT_BLOCKED_BY_ADMIN_END = 20479,
        AMSI_RESULT_DETECTED = 32768,
    }
}

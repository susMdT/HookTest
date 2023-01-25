using System;
using System.Linq;
using System.Runtime.InteropServices;

namespace ShittyHook
{
    public class NtWriteHook : FxHook
    {
        [UnmanagedFunctionPointer(CallingConvention.StdCall)]
        public delegate uint NtWriteVirtualMemory(
            IntPtr processHandle,
            IntPtr baseAddress,
            IntPtr buffer,
            uint bufferLength,
            ref UInt32 NumberOfBytesWritten);
        public static FxHook HookData;
        public NtWriteHook(IntPtr pNtWrite) : base(pNtWrite, (NtWriteVirtualMemory)Handler)
        {
            HookData = this;
            Install();
        }
        public static uint Handler(IntPtr processHandle, IntPtr baseAddress, IntPtr buffer, uint bufferLength, ref UInt32 NumberOfBytesWritten)
        {
            Marshal.Copy(HookData.src, 0, HookData.addr, HookData.nBytes); // temporarily remove hook
            Console.WriteLine("===========RECEIVED NTWRITE============");

            Console.WriteLine("Handle 0x{0:X}", (long)processHandle);
            Console.WriteLine("BaseAddress 0x{0:X}", (long)baseAddress);
            Console.WriteLine("Buffer 0x{0:X}", (long)buffer);
            Console.WriteLine("BufferLength 0x{0:X}", (long)bufferLength);
            Console.WriteLine("NumberOfBytesWritten 0x{0:X}", (long)NumberOfBytesWritten);

            object[] args = { processHandle, baseAddress, buffer, bufferLength, NumberOfBytesWritten };
            uint retVal = (uint)Marshal.GetDelegateForFunctionPointer(HookData.addr, typeof(NtWriteVirtualMemory)).DynamicInvoke(args);
            NumberOfBytesWritten = (UInt32)args[4];

            Console.WriteLine("NumberOfBytesWritten is now 0x{0:X}", (long)NumberOfBytesWritten);
            Console.WriteLine("NTSTATUS 0x{0:X}", (long)retVal);

            if (retVal == 0) // Let's read the bytes
            {
                Scanner.Scan(baseAddress, (int)NumberOfBytesWritten);
            }
            Console.WriteLine("=======================================\n");

            Marshal.Copy(HookData.dst, 0, HookData.addr, HookData.nBytes); // restore hook
            return retVal;
        }
    }
}

using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace ShittyHook
{
    public class FxHook : IDisposable
    {

        public int nBytes = 13;
        // movabs r11, address
        // jmp r11

        public IntPtr addr; // the function we are hooking
        Protection old;
        public byte[] src = new byte[13]; //source bytes
        public byte[] dst = new byte[13]; //trampoline

        public FxHook(IntPtr source, IntPtr destination)
        {
            VirtualProtect(source, (uint)nBytes, Protection.PAGE_EXECUTE_READWRITE, out old);
            Marshal.Copy(source, src, 0, nBytes); //copy the original 13 we will patch
            dst[0] = 0x49;
            dst[1] = 0XBB;
            var dx = BitConverter.GetBytes((long)destination);
            Array.Copy(dx, 0, dst, 2, 8);
            dst[10] = 0x41;
            dst[11] = 0xFF;
            dst[12] = 0xE3;
            addr = source;
        }
        public FxHook(IntPtr source, Delegate destination) :
            this(source, Marshal.GetFunctionPointerForDelegate(destination))
        {
        }

        public void Install()
        {
            Marshal.Copy(dst, 0, addr, nBytes);
        }

        public void Uninstall()
        {
            Marshal.Copy(src, 0, addr, nBytes);
        }

        public void Dispose()
        {
            Uninstall();
            Protection x;
            VirtualProtect(addr, (uint)nBytes, old, out x);
        }

        [DllImport("kernel32.dll", SetLastError = true)]
        static extern bool VirtualProtect(IntPtr lpAddress, uint dwSize, Protection flNewProtect, out Protection lpflOldProtect);

        public enum Protection
        {
            PAGE_NOACCESS = 0x01,
            PAGE_READONLY = 0x02,
            PAGE_READWRITE = 0x04,
            PAGE_WRITECOPY = 0x08,
            PAGE_EXECUTE = 0x10,
            PAGE_EXECUTE_READ = 0x20,
            PAGE_EXECUTE_READWRITE = 0x40,
            PAGE_EXECUTE_WRITECOPY = 0x80,
            PAGE_GUARD = 0x100,
            PAGE_NOCACHE = 0x200,
            PAGE_WRITECOMBINE = 0x400
        }
    }
}

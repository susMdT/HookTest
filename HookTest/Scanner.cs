using System;
using System.Collections.Generic;
using System.Linq;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading.Tasks;

namespace ShittyHook
{
    public class Scanner
    {
        public static void Scan(IntPtr address, int count)
        {
            
            byte[] scanning = new byte[count];
            byte[] calc = new byte[] { 0xfc, 0x48, 0x83, 0xe4, 0xf0, 0xe8, 0xc0, 0x00, 0x00, 0x00, 0x41, 0x51 };
            
            Marshal.Copy(address, scanning, 0, count);
            Console.WriteLine("[*] Scanning 0x{0:X} bytes", count);
            if (ArrayContainsArray(scanning, calc)) Console.WriteLine("[!] CALC MSFVENOM CODE DETECTED!");
            
            return;
        }
        public static bool ArrayContainsArray(byte[] container, byte[] containee)
        {
            if (container.Length < containee.Length)
            {
                return false;
            }

            for (int i = 0; i <= container.Length - containee.Length; i++)
            {
                bool match = true;
                for (int j = 0; j < containee.Length; j++)
                {
                    if (container[i + j] != containee[j])
                    {
                        match = false;
                        break;
                    }
                }
                if (match)
                {
                    return true;
                }
            }

            return false;
        }
    }
}

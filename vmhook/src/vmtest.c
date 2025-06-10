#include <windows.h>
#include <stdint.h>

typedef uint64_t u64;
typedef int (*handler_fn)(void);

static u64 key = 0x7F3D2149ULL;

static int real_handler(void) {
    MessageBoxA(NULL, "Real handler called!", "VMTest", MB_OK);
    return 0x12345678;
}

static int default_handler(void) {
    return 0x0;
}

// gave it its own section because im lazy
#pragma section(".vmtable", read, write)
__declspec(allocate(".vmtable"))
u64 vm_table[256];

BOOL APIENTRY DllMain(HMODULE h, DWORD reason, LPVOID reserved) {
    if (reason == DLL_PROCESS_ATTACH) {
        for (int i = 0; i < 256; i++)
            vm_table[i] = (u64)default_handler ^ key;
        vm_table[0x55] = (u64)real_handler ^ key;
    }
    return TRUE;
}

__declspec(dllexport) int RunVM(void) {
    handler_fn fn = (handler_fn)(vm_table[0x55] ^ key);
    return fn();
}

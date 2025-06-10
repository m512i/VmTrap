#include "vmhook.h"
#include <stdio.h>
#include <stdlib.h>

extern int __fastcall call_with_idx(uintptr_t fnptr, int idx);

uint64_t my_decrypt(uint64_t x) { return x ^ 0x7F3D2149ULL; }
uint64_t my_encrypt(uint64_t x) { return x ^ 0x7F3D2149ULL; }
void     my_edit(uint64_t* p, uint64_t v) {
    DWORD old; VirtualProtect(p,8,PAGE_EXECUTE_READWRITE,&old);
    *p = v; VirtualProtect(p,8,old,&old);
}

void my_vm_callback(vm_registers_t* regs, uint8_t idx) {
    printf("[vtrap] handler index = 0x%02X\n", idx);
    printf("[vtrap] handler virt = 0x%llx\n", (unsigned long long)vmctx->entries[idx].virt);
    printf("[vtrap] handler encrypted = 0x%llx\n", (unsigned long long)vmctx->entries[idx].encrypted);
    printf("[vtrap] handler decrypted = 0x%llx\n", (unsigned long long)vmctx->entries[idx].decrypted);
    
    typedef int (*orig_fn_t)(void);
    orig_fn_t orig = (orig_fn_t)vmctx->entries[idx].virt;
    int ret = orig();
    printf("[vtrap] original returned 0x%08X\n", ret);
    
    regs->rax = (uint64_t)ret;
}

void print_usage(const char* prog) {
    printf("Usage: %s --bin <path> --table <rva> --base <base>\n", prog);
    printf("  --bin   : Path to the protected binary\n");
    printf("  --table : RVA of the VM handler table (hex)\n");
    printf("  --base  : Original image base (hex)\n");
    exit(1);
}

void print_addr_info(const char* label, uint64_t addr) {
    printf("%s = 0x%llx\n", label, (unsigned long long)addr);
}

int main(int argc, char** argv) {
    char* bin_path = NULL;
    char* table_rva_str = NULL;
    char* image_base_str = NULL;

    for (int i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--bin") == 0 && i + 1 < argc) {
            bin_path = argv[++i];
        } else if (strcmp(argv[i], "--table") == 0 && i + 1 < argc) {
            table_rva_str = argv[++i];
        } else if (strcmp(argv[i], "--base") == 0 && i + 1 < argc) {
            image_base_str = argv[++i];
        }
    }

    if (!bin_path || !table_rva_str || !image_base_str) {
        print_usage(argv[0]);
    }

    HMODULE hmod = LoadLibraryA(bin_path);
    if (!hmod) {
        printf("Failed to load %s (error: %d)\n", bin_path, GetLastError());
        return 1;
    }

    uint64_t mod_base = (uint64_t)hmod;
    uint64_t img_base = strtoull(image_base_str, NULL, 16);
    uint64_t rva      = strtoul(table_rva_str, NULL, 16);
    uint64_t* table_addr = (uint64_t*)(mod_base + rva);

    printf("\n=== Address Information ===\n");
    print_addr_info("Module base", mod_base);
    print_addr_info("Image base", img_base);
    print_addr_info("Table RVA", rva);
    print_addr_info("Table address", (uint64_t)table_addr);
    print_addr_info("First table entry (encrypted)", table_addr[0]);
    
    vm_hook_t hook;
    vmhook_init(&hook, mod_base, img_base, my_decrypt, my_encrypt, my_edit, table_addr);
    vmctx = &hook;

    printf("\n=== Hook Initialization ===\n");
    print_addr_info("vtrap_encrypted", hook.vtrap_encrypted);
    print_addr_info("Handler 0x55 encrypted", hook.entries[0x55].encrypted);
    print_addr_info("Handler 0x55 decrypted", hook.entries[0x55].decrypted);
    print_addr_info("Handler 0x55 virt", hook.entries[0x55].virt);

    vmctx->entries[0x55].callback = my_vm_callback;

    vmhook_start(vmctx);

    printf("\n=== After Hook ===\n");
    print_addr_info("Table[0] after hook", table_addr[0]);
    print_addr_info("Expected vtrap_encrypted", hook.vtrap_encrypted);

    printf("\n=== Running VM via direct table call ===\n");
    const uint8_t idx = 0x55;
    uint64_t enc = table_addr[idx];
    uint64_t trap_abs = enc ^ 0x7F3D2149ULL;  
    printf("Decrypt table[%#x]: 0x%llx -> calling __vtrap at that address\n", 
           idx, (unsigned long long)trap_abs);
    
    int vmres = call_with_idx(trap_abs, idx);
    printf("Direct table VM returned 0x%08X\n", vmres);

    vmhook_stop(vmctx);
    return 0;
}
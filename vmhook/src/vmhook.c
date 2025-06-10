#include "vmhook.h"
#include <stdio.h>
#include <stdlib.h>

vm_hook_t* vmctx = NULL;

void vmhook_init(
    vm_hook_t* h,
    uint64_t   module_base,
    uint64_t   image_base,
    uint64_t (*decrypt)(uint64_t),
    uint64_t (*encrypt)(uint64_t),
    void     (*edit)(uint64_t*, uint64_t),
    uint64_t* table_addr
) {
    h->module_base  = module_base;
    h->image_base   = image_base;
    h->decrypt      = decrypt;
    h->encrypt      = encrypt;
    h->edit         = edit;
    h->table_addr   = table_addr;

    for (int i = 0; i < 256; ++i) {
        uint64_t enc = table_addr[i];
        uint64_t dec = decrypt(enc);  
        h->entries[i].encrypted = enc;
        h->entries[i].decrypted = dec;
        h->entries[i].virt      = dec;  
        h->entries[i].callback  = NULL;  
    }

    extern void __vtrap(void);
    uint64_t trap_abs = (uint64_t)&__vtrap;  
    h->vtrap_encrypted = encrypt(trap_abs);  
}

void vmhook_start(vm_hook_t* h) {
    for (int i = 0; i < 256; ++i) {
        h->edit(&h->table_addr[i], h->vtrap_encrypted);
    }
}

void vmhook_stop(vm_hook_t* h) {
    for (int i = 0; i < 256; ++i) {
        h->edit(&h->table_addr[i], h->entries[i].encrypted);
    }
}

void vtrap_wrapper(vm_registers_t* regs, uint8_t handler_idx) {
    if (vmctx->entries[handler_idx].callback)
        vmctx->entries[handler_idx].callback(regs, handler_idx);
}

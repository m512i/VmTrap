#pragma once
#include <stdint.h>
#include <windows.h>

typedef struct vm_registers vm_registers_t;
typedef struct vm_hook_t    vm_hook_t;

extern vm_hook_t* vmctx;

typedef struct {
    uint64_t virt;       
    uint64_t encrypted;  
    uint64_t decrypted;  
    void (*callback)(vm_registers_t* regs, uint8_t idx);
} vm_entry_t;

struct vm_hook_t {
    uint64_t*      table_addr;   
    vm_entry_t     entries[256]; 
    uint64_t       module_base;
    uint64_t       image_base;
    uint64_t       (*decrypt)(uint64_t);
    uint64_t       (*encrypt)(uint64_t);
    void           (*edit)(uint64_t* ptr, uint64_t val);
    uint64_t       vtrap_encrypted; 
};

struct vm_registers {
    uint8_t  xmm[16][16];
    uint64_t r15, r14, r13, r12, r11, r10, r9, r8;
    uint64_t rbp, rdi, rsi, rdx, rcx, rbx, rax, rflags;
    uint64_t vm_handler;  
};

void vmhook_init(
    vm_hook_t* h,
    uint64_t   module_base,
    uint64_t   image_base,
    uint64_t (*decrypt)(uint64_t),
    uint64_t (*encrypt)(uint64_t),
    void     (*edit)(uint64_t*, uint64_t),
    uint64_t* table_addr   
);

void vmhook_start(vm_hook_t* h);

void vmhook_stop(vm_hook_t* h);

void vtrap_wrapper(vm_registers_t* regs, uint8_t handler_idx);

extern void __vtrap(void); 
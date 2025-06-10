.code

call_with_idx PROC
    mov rax, rdx        
    mov r11, rcx         
    call r11            
    ret
call_with_idx ENDP

end 
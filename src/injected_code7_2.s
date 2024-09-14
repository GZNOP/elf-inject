BITS 64

SECTION .text
global main

main:
    ; save context
    push rax
    push rcx
    push rdx
    push rsi
    push rdi
    push r11

    mov rax, 1
    mov rdi, 1
    lea rsi, [rel msg] ; rel: relative address (perfect for an injection)
    mov rdx, $24
    syscall

    pop r11
    pop rdi
    pop rsi
    pop rdx
    pop rcx
    pop rax

    ret

msg db "je suis trop un hacker", 10, 0 


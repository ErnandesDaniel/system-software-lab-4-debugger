bits 64
default rel
section .text

global main
extern puts
extern getchar
extern putchar
extern printf

main:
    push rbp
    mov rbp, rsp
    sub rsp, 168
BB_0:
    lea rax, [str_0]
    mov [rbp + -8], rax
line_16:
    mov rax, [rbp + -8]
    mov [rbp + -16], rax
line_18:
    mov rcx, [rbp + -16]
    sub rsp, 32
    call puts
    add rsp, 32
    mov [rbp + -40], eax
line_20:
    sub rsp, 32
    call getchar
    add rsp, 32
    mov [rbp + -48], eax
    mov eax, [rbp + -48]
    mov [rbp + -56], eax
line_21:
    mov ecx, [rbp + -56]
    sub rsp, 32
    call putchar
    add rsp, 32
    mov [rbp + -80], eax
    mov eax, 10
    mov [rbp + -88], eax
line_22:
    mov ecx, [rbp + -88]
    sub rsp, 32
    call putchar
    add rsp, 32
    mov [rbp + -96], eax
    lea rax, [str_1]
    mov [rbp + -104], rax
    mov eax, 10
    mov [rbp + -112], eax
line_24:
    mov rcx, [rbp + -104]
    mov edx, [rbp + -112]
    sub rsp, 32
    call printf
    add rsp, 32
    mov [rbp + -120], eax
    mov eax, 10
    mov [rbp + -128], eax
line_26:
    mov ecx, [rbp + -128]
    sub rsp, 32
    call putchar
    add rsp, 32
    mov [rbp + -136], eax
    mov eax, 27
    mov [rbp + -144], eax
    mov eax, [rbp + -144]
; Очистка стека и возврат
    leave       ; эквивалент: mov rsp, rbp; pop rbp
    ret         ; возвращаем eax как результат
main_end:

section .rodata
str_0 db 72, 101, 108, 108, 111, 44, 32, 87, 111, 114, 108, 100, 33, 46, 32, 69, 110, 116, 101, 114, 32, 115, 111, 109, 101, 32, 115, 121, 109, 98, 111, 108, 0
str_1 db 37, 100, 0

section .debug_str
dbg_str_main db 'main', 0
dbg_str_s db 's', 0
dbg_str_c db 'c', 0

section .debug_info
    ; === Функция main ===
    dq dbg_str_main                 ; указатель на имя
    dq main                         ; старт
    dq main_end                     ; конец
    dd 0                          ; параметров: 0
    dd 2                         ; локальных: 2
    ; Переменная s
    dq dbg_str_s                    ; имя
    dd 1                            ; тип: string
    dd -16                           ; смещение
    ; Переменная c
    dq dbg_str_c                    ; имя
    dd 0                            ; тип: int
    dd -56                           ; смещение

section .debug_line
dq line_16
dd 16
dq line_18
dd 18
dq line_20
dd 20
dq line_21
dd 21
dq line_22
dd 22
dq line_24
dd 24
dq line_26
dd 26

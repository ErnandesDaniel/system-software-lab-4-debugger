bits 64
default rel
section .text

global main
extern puts
extern getchar
extern putchar
extern printf

; Первая метка в .text — для вычисления смещений
.text_start:
main:
    int3
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

section .dbstr progbits alloc noexec readonly
dbg_str_start:              ; Метка начала секции строк
dbg_str_main db 'main', 0
dbg_str_s    db 's', 0
dbg_str_c    db 'c', 0

section .dbinfo progbits alloc noexec readonly
    ; === Функция main ===
    ; Вычисляем смещение каждой строки от начала секции .dbstr
    dq dbg_str_main - dbg_str_start ; смещение 0
    dd 0          ; params
    dd 2          ; locals

    ; Переменная s
    dq dbg_str_s - dbg_str_start    ; теперь это будет число 5 (смещение)
    dd 1                            ; тип: string
    dd -16                           ; ИСПРАВЛЕНО: в коде mov [rbp-8], rax

    ; Переменная c
    dq dbg_str_c - dbg_str_start    ; теперь это число 7
    dd 0                            ; тип: int
    dd -56                          ; смещение (совпадает с line_20)

section .dbline progbits alloc noexec readonly
    dd line_16 - .text_start, 16
    dd line_18 - .text_start, 18
    dd line_20 - .text_start, 20
    dd line_21 - .text_start, 21
    dd line_22 - .text_start, 22
    dd line_24 - .text_start, 24
    dd line_26 - .text_start, 26
    dd 0, 0       ; конец
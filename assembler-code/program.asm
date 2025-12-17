bits 64
default rel
section .text

global main
global line_3
global line_5
global line_last
global .dbinfo   ; <--- добавить это, чтобы найти адрес секции

main:
    push rbp
    mov rbp, rsp
    sub rsp, 72
main_start:; <-- Метка прямо перед первой полезной строкой
BB_0:
    lea rax, [str_0]
    mov [rbp + -8], rax
line_3:
    mov rax, [rbp + -8]
    mov [rbp + -16], rax
    mov eax, 10
    mov [rbp + -32], eax
line_5:
    mov eax, [rbp + -32]
    mov [rbp + -40], eax
    mov eax, [rbp + -40]
line_last:
; Очистка стека и возврат
    leave       ; эквивалент: mov rsp, rbp; pop rbp
    ret         ; возвращаем eax как результат
main_end:

section .rodata
str_0 db 72, 101, 108, 108, 111, 44, 32, 87, 111, 114, 108, 100, 33, 46, 32, 69, 110, 116, 101, 114, 32, 115, 111, 109, 101, 32, 115, 121, 109, 98, 111, 108, 0

section .dbstr
dbg_str_main db 'main', 0
dbg_str_s db 's', 0
dbg_str_c db 'c', 0

section .dbinfo
    ; === Функция main ===
    dq dbg_str_main                 ; указатель на имя
    dq main_start                   ; Реальный адрес начала кода (для отладчика)
    dq main_end                     ; Адрес конца кода (чтобы знать границы функции)
    dd 2                         ; локальных: 2
    ; Переменная s
    dq dbg_str_s                    ; имя
    dd 1                            ; тип: string
    dd -16                           ; смещение
    ; Переменная c
    dq dbg_str_c                    ; имя
    dd 0                            ; тип: int
    dd -40                           ; смещение

section .dbline
    dq line_3
    dq 3
    dq line_5
    dq 5
    dq line_last
    dq 6
    dq 0, 0 ; Конец таблицы
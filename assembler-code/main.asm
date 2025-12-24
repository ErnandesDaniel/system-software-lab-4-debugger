bits 64
default rel
section .text

global main
global line_12
global line_14
global line_16
global main_before_ret
global .dbinfo

extern square

main:
    push rbp
    mov rbp, rsp
    sub rsp, 136
main_start:
BB_0:
    lea rax, [str_0]
    mov [rbp + -40], rax
line_12:
    mov rax, [rbp + -40]
    mov [rbp + -48], rax
    mov eax, 10
    mov [rbp + -64], eax
line_14:
    mov eax, [rbp + -64]
    mov [rbp + -72], eax
    mov eax, 3
    mov [rbp + -88], eax
line_16:
    mov ecx, [rbp + -88]
    sub rsp, 32
    call square
    add rsp, 32
    mov [rbp + -96], eax
    mov eax, [rbp + -96]
    mov [rbp + -104], eax
    mov eax, [rbp + -104]
main_before_ret:
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
dbg_str_b db 'b', 0

section .dbinfo
    align 16                    ; Гарантируем начало структуры на границе 16 байт
    ; === Функция main ===
    dq dbg_str_main                 ; указатель на имя
    dq main_start                   ; Реальный адрес начала кода (для отладчика)
    dq main_end                     ; конец
    dd 3                         ; локальных: 3
    dd 0
    ; Переменная s
    dq dbg_str_s                    ; имя
    dd 1                            ; тип: string
    dd -48                           ; смещение
    ; Переменная c
    dq dbg_str_c                    ; имя
    dd 0                            ; тип: int
    dd -72                           ; смещение
    ; Переменная b
    dq dbg_str_b                    ; имя
    dd 0                            ; тип: int
    dd -104                           ; смещение
    align 16                    ; Конец секции в этом файле

section .dbline
align 16                    ; Начало блока строк
dq main_start       ; Указываем, чьи это строки
dq 4                ; Сколько строк в этом блоке
dq line_12
dq 12
dq line_14
dq 14
dq line_16
dq 16
dq main_before_ret
dq 17
align 16

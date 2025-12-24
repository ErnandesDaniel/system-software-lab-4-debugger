bits 64
default rel
section .text

global square
global line_5
global square_before_ret
global .dbinfo


square:
    push rbp
    mov rbp, rsp
    mov [rbp + -8], rcx
    sub rsp, 72
square_start:
BB_0:
    mov eax, 6
    mov [rbp + -40], eax
line_5:
    mov eax, [rbp + -40]
    mov [rbp + -48], eax
    mov eax, [rbp + -8]
    mov ebx, [rbp + -8]
    imul eax, ebx
    mov [rbp + -64], eax
    mov eax, [rbp + -64]
square_before_ret:
; Очистка стека и возврат
    leave       ; эквивалент: mov rsp, rbp; pop rbp
    ret         ; возвращаем eax как результат
square_end:

section .dbstr
dbg_str_square db 'square', 0
dbg_str_x db 'x', 0
dbg_str_b db 'b', 0

section .dbinfo
    align 16                    ; Гарантируем начало структуры на границе 16 байт
    ; === Функция square ===
    dq dbg_str_square                 ; указатель на имя
    dq square_start                   ; Реальный адрес начала кода (для отладчика)
    dq square_end                     ; конец
    dd 2                         ; локальных: 2
    dd 0
    ; Переменная x
    dq dbg_str_x                    ; имя
    dd 0                            ; тип: int
    dd -8                           ; смещение
    ; Переменная b
    dq dbg_str_b                    ; имя
    dd 0                            ; тип: int
    dd -48                           ; смещение
    align 16                    ; Конец секции в этом файле

section .dbline
align 16                    ; Начало блока строк
dq square_start       ; Указываем, чьи это строки
dq 2                ; Сколько строк в этом блоке
dq line_5
dq 5
dq square_before_ret
dq 6
align 16

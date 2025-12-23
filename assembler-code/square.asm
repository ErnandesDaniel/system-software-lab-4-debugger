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
    sub rsp, 72
square_start:
BB_0:
    mov eax, 6
    mov [rbp + -16], eax
line_5:
    mov eax, [rbp + -16]
    mov [rbp + -24], eax
    mov eax, ecx
    mov ebx, ecx
    imul eax, ebx
    mov [rbp + -56], eax
    mov eax, [rbp + -56]
square_before_ret:
; Очистка стека и возврат
    leave       ; эквивалент: mov rsp, rbp; pop rbp
    ret         ; возвращаем eax как результат
square_end:

section .debug_str
dbg_str_square db 'square', 0
dbg_str_x db 'x', 0
dbg_str_b db 'b', 0

section .debug_info
    ; === Функция square ===
    dq dbg_str_square                 ; указатель на имя
    dq square_start                   ; Реальный адрес начала кода (для отладчика)
    dq square_end                     ; конец
    dd 2                         ; локальных: 2
    ; Переменная x
    dq dbg_str_x                    ; имя
    dd 0                            ; тип: int
    dd -8                           ; смещение
    ; Переменная b
    dq dbg_str_b                    ; имя
    dd 0                            ; тип: int
    dd -24                           ; смещение

section .debug_line
dq line_5
dq 5
dq square_before_ret
dq 6
dq 0, 0 ; Конец таблицы

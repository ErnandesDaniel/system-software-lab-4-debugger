#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <capstone/capstone.h>

// Цветовая разметка
#define CLR_RESET  "\x1b[0m"
#define CLR_HEADER "\x1b[1;36m"
#define CLR_ADDR   "\x1b[33m"
#define CLR_FUNC   "\x1b[1;32m"
#define CLR_ERR    "\x1b[31m"

#define ALIGN16(x) (((x) + 15) & ~15)

#pragma pack(push, 1)
typedef struct {
    uint64_t name_ptr;
    uint32_t type;    // 0 - int, 1 - string
    int32_t offset;   // Смещение относительно RBP
} VarEntry;

typedef struct {
    uint64_t func_name_ptr;
    uint64_t start_addr;
    uint64_t end_addr;
    uint32_t var_count;
    uint32_t padding; // Заполнитель для выравнивания (dd 0 в ASM)
} FuncEntry;
#pragma pack(pop)

// Глобальные данные отладчика
uint64_t g_dbinfo_addr = 0;
uint64_t g_dbline_addr = 0;
uint64_t g_bp_addrs[100];
unsigned char g_orig_bytes[100];
int g_bp_count = 0;

// Прототипы вспомогательных функций
uint64_t GetSectionRVA(const char* filename, const char* sectionName);
void handle_interactive_menu(HANDLE hProc, HANDLE hThread);
const char* find_func_info(HANDLE hProc, uint64_t rip, FuncEntry* out_f, uint64_t* out_f_ptr);
void print_variable(HANDLE hProc, CONTEXT* ctx, const char* var_name);
void print_backtrace(HANDLE hProc, uint64_t rbp, uint64_t rip);
void disassemble_at(HANDLE hProc, uint64_t addr, int inst_count);

// ==========================================================
// ОСНОВНАЯ ФУНКЦИЯ MAIN
// ==========================================================
int main(int argc, char* argv[]) {
    system("chcp 65001 > nul");
    if (argc < 2) {
        printf("Использование: %s <program.exe>\n", argv[0]);
        return 1;
    }

    uint64_t rva_info = GetSectionRVA(argv[1], ".dbinfo");
    uint64_t rva_line = GetSectionRVA(argv[1], ".dbline");

    if (!rva_info) {
        printf(CLR_ERR "[-] Ошибка: Секция .dbinfo не найдена. Проверьте компилятор.\n" CLR_RESET);
        return 1;
    }

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    if (!CreateProcessA(argv[1], NULL, NULL, NULL, FALSE, DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &si, &pi)) {
        printf(CLR_ERR "[-] Не удалось запустить процесс.\n" CLR_RESET);
        return 1;
    }

    DEBUG_EVENT de;
    int system_bp_done = 0;

    while (WaitForDebugEvent(&de, INFINITE)) {
        if (de.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT) {
            uint64_t base = (uint64_t)de.u.CreateProcessInfo.lpBaseOfImage;
            g_dbinfo_addr = base + rva_info;
            g_dbline_addr = base + rva_line;
            printf("[+] Процесс загружен. База: 0x%llx, .dbinfo: 0x%llx\n", base, g_dbinfo_addr);

        } else if (de.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
            DWORD code = de.u.Exception.ExceptionRecord.ExceptionCode;

            if (code == EXCEPTION_BREAKPOINT) {
                if (!system_bp_done) {
                    // Инициализация точек останова из .dbline
                    system_bp_done = 1;
                    for (int i = 0; i < 100; i++) {
                        uint64_t line_addr_val = 0;
                        // В .dbline структура: [указатель на функцию], [кол-во строк], [адрес метки], [номер строки]...
                        // Для упрощения ищем метки line_X
                        ReadProcessMemory(pi.hProcess, (LPCVOID)(g_dbline_addr + 16 + (i * 16)), &line_addr_val, 8, NULL);
                        if (line_addr_val == 0) break;

                        ReadProcessMemory(pi.hProcess, (LPVOID)line_addr_val, &g_orig_bytes[g_bp_count], 1, NULL);
                        unsigned char int3 = 0xCC;
                        WriteProcessMemory(pi.hProcess, (LPVOID)line_addr_val, &int3, 1, NULL);
                        g_bp_addrs[g_bp_count++] = line_addr_val;
                    }
                    printf("[+] Установлено %d точек останова.\n", g_bp_count);
                } else {
                    // Остановка на Breakpoint
                    CONTEXT ctx; ctx.ContextFlags = CONTEXT_FULL;
                    GetThreadContext(pi.hThread, &ctx);
                    ctx.Rip--; // Возвращаемся к началу инструкции INT3
                    SetThreadContext(pi.hThread, &ctx);

                    handle_interactive_menu(pi.hProcess, pi.hThread);

                    // Временное восстановление байта для шага (упрощенно)
                    for(int i = 0; i < g_bp_count; i++) {
                        if (g_bp_addrs[i] == ctx.Rip)
                            WriteProcessMemory(pi.hProcess, (LPVOID)ctx.Rip, &g_orig_bytes[i], 1, NULL);
                    }
                }
            } else if (code == EXCEPTION_SINGLE_STEP) {
                handle_interactive_menu(pi.hProcess, pi.hThread);
            }
        } else if (de.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
            printf("\n--- Процесс завершен ---\n");
            break;
        }
        ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
    }
    return 0;
}

// ==========================================================
// ЛОГИКА ИНТЕРФЕЙСА
// ==========================================================
void handle_interactive_menu(HANDLE hProc, HANDLE hThread) {
    CONTEXT ctx; ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(hThread, &ctx);

    FuncEntry current_f;
    const char* f_name = find_func_info(hProc, ctx.Rip, &current_f, NULL);

    printf("\nОстановка: " CLR_ADDR "0x%llx" CLR_RESET " в " CLR_FUNC "%s" CLR_RESET "\n", ctx.Rip, f_name);
    disassemble_at(hProc, ctx.Rip, 1);

    char input[256];
    while (1) {
        printf(CLR_HEADER "dbg> " CLR_RESET);
        if (!fgets(input, sizeof(input), stdin)) break;

        char cmd[16], arg[64] = {0};
        int count = sscanf(input, "%s %s", cmd, arg);
        if (count < 1) continue;

        if (!strcmp(cmd, "n")) break; // Continue
        if (!strcmp(cmd, "s")) {      // Step
            ctx.ContextFlags = CONTEXT_CONTROL;
            GetThreadContext(hThread, &ctx);
            ctx.EFlags |= 0x100;
            SetThreadContext(hThread, &ctx);
            break;
        }
        if (!strcmp(cmd, "p")) { print_variable(hProc, &ctx, arg); }
        if (!strcmp(cmd, "bt")) { print_backtrace(hProc, ctx.Rbp, ctx.Rip); }
        if (!strcmp(cmd, "r")) {
            printf("RAX: %016llx  RBX: %016llx\n", ctx.Rax, ctx.Rbx);
            printf("RBP: %016llx  RSP: %016llx  RIP: %016llx\n", ctx.Rbp, ctx.Rsp, ctx.Rip);
        }
        if (!strcmp(cmd, "dis")) disassemble_at(hProc, ctx.Rip, 10);
        if (!strcmp(cmd, "q")) { TerminateProcess(hProc, 0); exit(0); }
        if (!strcmp(cmd, "h")) {
            printf("Команды: n (next), s (step), p <var>, bt (backtrace), r (regs), dis (asm), q (quit)\n");
        }
    }
}

// ==========================================================
// ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ (ПОИСК И ЧТЕНИЕ)
// ==========================================================

const char* find_func_info(HANDLE hProc, uint64_t rip, FuncEntry* out_f, uint64_t* out_f_ptr) {
    static char name_buf[64];
    uint64_t ptr = g_dbinfo_addr;

    for (int i = 0; i < 20; i++) {
        FuncEntry f;
        if (!ReadProcessMemory(hProc, (LPCVOID)ptr, &f, sizeof(f), NULL)) break;

        // Обработка выравнивания (если попали на пустые байты между функциями)
        if (f.func_name_ptr == 0) {
            ptr = ALIGN16(ptr + 1);
            continue;
        }

        if (rip >= f.start_addr && rip <= f.end_addr) {
            ReadProcessMemory(hProc, (LPCVOID)f.func_name_ptr, name_buf, 63, NULL);
            if (out_f) *out_f = f;
            if (out_f_ptr) *out_f_ptr = ptr;
            return name_buf;
        }

        // Прыгаем к следующему блоку: заголовок + переменные, затем выравнивание
        ptr += sizeof(FuncEntry) + (f.var_count * sizeof(VarEntry));
        ptr = ALIGN16(ptr);
    }
    return "unknown";
}

void print_variable(HANDLE hProc, CONTEXT* ctx, const char* var_name) {
    FuncEntry f;
    uint64_t f_ptr;
    if (strcmp(find_func_info(hProc, ctx->Rip, &f, &f_ptr), "unknown") == 0) {
        printf("[-] Не удалось определить контекст функции.\n");
        return;
    }

    uint64_t vptr = f_ptr + sizeof(FuncEntry);
    for (uint32_t i = 0; i < f.var_count; i++) {
        VarEntry v;
        ReadProcessMemory(hProc, (LPCVOID)vptr, &v, sizeof(v), NULL);
        char vn[64] = {0};
        ReadProcessMemory(hProc, (LPCVOID)v.name_ptr, vn, 63, NULL);

        if (strcmp(vn, var_name) == 0) {
            uint64_t target_addr = ctx->Rbp + v.offset;
            if (v.type == 0) { // int
                int val;
                ReadProcessMemory(hProc, (LPCVOID)target_addr, &val, 4, NULL);
                printf(CLR_FUNC "%s" CLR_RESET " = %d\n", vn, val);
            } else { // string
                uint64_t str_ptr;
                ReadProcessMemory(hProc, (LPCVOID)target_addr, &str_ptr, 8, NULL);
                char str_val[128] = {0};
                ReadProcessMemory(hProc, (LPCVOID)str_ptr, str_val, 127, NULL);
                printf(CLR_FUNC "%s" CLR_RESET " = \"%s\"\n", vn, str_val);
            }
            return;
        }
        vptr += sizeof(VarEntry);
    }
    printf("[-] Переменная '%s' не найдена.\n", var_name);
}

void print_backtrace(HANDLE hProc, uint64_t rbp, uint64_t rip) {
    printf(CLR_HEADER "\n--- Стек вызовов ---\n" CLR_RESET);
    int frame = 0;
    while (rbp != 0 && frame < 10) {
        printf("#%d  " CLR_ADDR "0x%llx" CLR_RESET " в " CLR_FUNC "%s\n",
               frame++, rip, find_func_info(hProc, rip, NULL, NULL));

        uint64_t next_rbp, next_rip;
        if (!ReadProcessMemory(hProc, (LPCVOID)rbp, &next_rbp, 8, NULL)) break;
        if (!ReadProcessMemory(hProc, (LPCVOID)(rbp + 8), &next_rip, 8, NULL)) break;
        rbp = next_rbp;
        rip = next_rip;
    }
}

void disassemble_at(HANDLE hProc, uint64_t addr, int inst_count) {
    csh handle;
    cs_insn *insn;
    uint8_t code[128];
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) return;

    if (ReadProcessMemory(hProc, (LPCVOID)addr, code, sizeof(code), NULL)) {
        size_t count = cs_disasm(handle, code, sizeof(code), addr, inst_count, &insn);
        if (count > 0) {
            for (size_t j = 0; j < count; j++) {
                printf("  %s " CLR_ADDR "0x%llx:" CLR_RESET " %-8s %s\n",
                       (insn[j].address == addr ? "=>" : "  "),
                       insn[j].address, insn[j].mnemonic, insn[j].op_str);
            }
            cs_free(insn, count);
        }
    }
    cs_close(&handle);
}

uint64_t GetSectionRVA(const char* filename, const char* sectionName) {
    HANDLE hFile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return 0;

    HANDLE hMap = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    LPVOID p = MapViewOfFile(hMap, FILE_MAP_READ, 0, 0, 0);

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)p + ((PIMAGE_DOS_HEADER)p)->e_lfanew);
    PIMAGE_SECTION_HEADER s = IMAGE_FIRST_SECTION(nt);
    uint64_t rva = 0;

    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (!strncmp((char*)s[i].Name, sectionName, 8)) {
            rva = s[i].VirtualAddress;
            break;
        }
    }

    UnmapViewOfFile(p); CloseHandle(hMap); CloseHandle(hFile);
    return rva;
}
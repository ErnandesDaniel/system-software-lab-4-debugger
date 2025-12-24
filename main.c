#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <capstone/capstone.h>

// Цветовая разметка для удобства CLI
#define CLR_RESET  "\x1b[0m"
#define CLR_HEADER "\x1b[1;36m"
#define CLR_ADDR   "\x1b[33m"
#define CLR_FUNC   "\x1b[1;32m"
#define CLR_ERR    "\x1b[31m"

#pragma pack(push, 1)
typedef struct {
    uint64_t name_ptr;
    uint32_t type;
    int32_t offset;
} VarEntry;

typedef struct {
    uint64_t func_name_ptr;
    uint64_t start_addr;
    uint64_t end_addr;
    uint32_t var_count;
} FuncEntry;
#pragma pack(pop)

uint64_t g_dbinfo_addr = 0;
uint64_t g_dbline_addr = 0;
uint64_t g_bp_addrs[100];
unsigned char g_orig_bytes[100];
int g_bp_count = 0;

const char* g_reg_names[] = { "RAX", "RDX", "RCX", "RBX", "RSI", "RDI", "RBP", "RSP", "R8", "R9", "R10", "R11", "R12", "R13", "R14", "R15", "RIP" };

// --- Прототипы ---
uint64_t GetSectionRVA(const char* filename, const char* sectionName);
void handle_interactive_menu(HANDLE hProc, HANDLE hThread);
void print_backtrace(HANDLE hProc, uint64_t rbp, uint64_t rip);
const char* find_func_name(HANDLE hProc, uint64_t addr);
void disassemble_at(HANDLE hProc, uint64_t addr, int inst_count);

int main(int argc, char* argv[]) {
    system("chcp 65001 > nul");
    if (argc < 2) { printf("Usage: %s <program.exe> [line_number]\n", argv[0]); return 1; }

    uint64_t rva_info = GetSectionRVA(argv[1], ".dbinfo");
    uint64_t rva_line = GetSectionRVA(argv[1], ".dbline");
    if (!rva_info || !rva_line) { printf(CLR_ERR "[-] Ошибка: Секции .dbinfo/.dbline не найдены.\n" CLR_RESET); return 1; }

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    if (!CreateProcessA(argv[1], NULL, NULL, NULL, FALSE, DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &si, &pi)) return 1;

    DEBUG_EVENT de;
    int system_bp_done = 0;

    while (WaitForDebugEvent(&de, INFINITE)) {
        if (de.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT) {
            uint64_t base = (uint64_t)de.u.CreateProcessInfo.lpBaseOfImage;
            g_dbinfo_addr = base + rva_info;
            g_dbline_addr = base + rva_line;
        } else if (de.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
            DWORD code = de.u.Exception.ExceptionRecord.ExceptionCode;
            if (code == EXCEPTION_BREAKPOINT) {
                if (!system_bp_done) {
                    system_bp_done = 1;
                    for (int i = 0; i < 100; i++) {
                        uint64_t addr_val = 0;
                        ReadProcessMemory(pi.hProcess, (LPCVOID)(g_dbline_addr + (i * 16)), &addr_val, 8, NULL);
                        if (addr_val == 0) break;
                        ReadProcessMemory(pi.hProcess, (LPVOID)addr_val, &g_orig_bytes[g_bp_count], 1, NULL);
                        unsigned char int3 = 0xCC;
                        WriteProcessMemory(pi.hProcess, (LPVOID)addr_val, &int3, 1, NULL);
                        g_bp_addrs[g_bp_count++] = addr_val;
                    }
                } else {
                    CONTEXT ctx; ctx.ContextFlags = CONTEXT_FULL;
                    GetThreadContext(pi.hThread, &ctx);
                    ctx.Rip--;
                    SetThreadContext(pi.hThread, &ctx);
                    handle_interactive_menu(pi.hProcess, pi.hThread);
                    for(int i = 0; i < g_bp_count; i++)
                        if (g_bp_addrs[i] == ctx.Rip)
                            WriteProcessMemory(pi.hProcess, (LPVOID)ctx.Rip, &g_orig_bytes[i], 1, NULL);
                }
            } else if (code == EXCEPTION_SINGLE_STEP) {
                handle_interactive_menu(pi.hProcess, pi.hThread);
            }
        } else if (de.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) break;
        ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
    }
    return 0;
}

const char* find_func_name(HANDLE hProc, uint64_t addr) {
    static char name_buf[64];
    uint64_t ptr = g_dbinfo_addr;

    printf(CLR_HEADER "\n[v] Поиск функции для RIP: 0x%llx\n" CLR_RESET, addr);

    for (int i = 0; i < 20; i++) { // Ограничим 20 записями для теста
        FuncEntry f;
        if (!ReadProcessMemory(hProc, (LPCVOID)ptr, &f, sizeof(f), NULL)) {
            printf(CLR_ERR "[-] Не удалось прочитать память по адресу 0x%llx\n" CLR_RESET, ptr);
            break;
        }

        // Если встретили нули (выравнивание линковщика)
        if (f.func_name_ptr == 0) {
            printf("  [?] Смещение 0x%llx: Нулевой указатель (пропуск 8 байт)\n", ptr);
            ptr += 8;
            continue;
        }

        // Читаем имя функции для вывода
        char current_f_name[64] = {0};
        ReadProcessMemory(hProc, (LPCVOID)f.func_name_ptr, current_f_name, 63, NULL);

        printf("  [+] Проверка: " CLR_FUNC "%s" CLR_RESET "\n", current_f_name);
        printf("      Диапазон: 0x%llx - 0x%llx\n", f.start_addr, f.end_addr);

        if (addr >= f.start_addr && addr <= f.end_addr) {
            printf(CLR_HEADER "      [!] Найдено совпадение!\n" CLR_RESET);
            strcpy(name_buf, current_f_name);
            return name_buf;
        }

        // Рассчитываем адрес следующей функции:
        // Текущий адрес + размер заголовка + (количество переменных * размер одной записи переменной)
        uint64_t next_ptr = ptr + sizeof(f) + (f.var_count * sizeof(VarEntry));
        printf("      Переменных: %d, смещаемся к 0x%llx\n", f.var_count, next_ptr);

        ptr = next_ptr;
    }

    return "unknown_func";
}

void print_backtrace(HANDLE hProc, uint64_t rbp, uint64_t rip) {
    printf(CLR_HEADER "\n--- Call Stack ---\n" CLR_RESET);
    int frame = 0;
    uint64_t curr_rbp = rbp;
    uint64_t curr_rip = rip;

    while (curr_rbp != 0 && frame < 10) {
        printf("#%d  " CLR_ADDR "0x%llx" CLR_RESET " in " CLR_FUNC "%s\n" CLR_RESET,
               frame++, curr_rip, find_func_name(hProc, curr_rip));

        uint64_t next_rbp, ret_addr;
        if (!ReadProcessMemory(hProc, (LPCVOID)curr_rbp, &next_rbp, 8, NULL)) break;
        if (!ReadProcessMemory(hProc, (LPCVOID)(curr_rbp + 8), &ret_addr, 8, NULL)) break;

        curr_rbp = next_rbp;
        curr_rip = ret_addr;
    }
}

void handle_interactive_menu(HANDLE hProc, HANDLE hThread) {
    CONTEXT ctx; ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(hThread, &ctx);

    printf("\nStopped at " CLR_ADDR "0x%llx" CLR_RESET " (" CLR_FUNC "%s" CLR_RESET ")\n",
           ctx.Rip, find_func_name(hProc, ctx.Rip));
    disassemble_at(hProc, ctx.Rip, 1);

    char input[256];
    while (1) {
        printf(CLR_HEADER "dbg> " CLR_RESET);
        if (!fgets(input, sizeof(input), stdin)) break;
        char cmd[16], arg[64];
        int count = sscanf(input, "%s %s", cmd, arg);
        if (count < 1) continue;

        if (!strcmp(cmd, "n")) break;
        if (!strcmp(cmd, "s")) {
            ctx.ContextFlags = CONTEXT_CONTROL;
            GetThreadContext(hThread, &ctx);
            ctx.EFlags |= 0x100;
            SetThreadContext(hThread, &ctx);
            break;
        }
        if (!strcmp(cmd, "bt")) { print_backtrace(hProc, ctx.Rbp, ctx.Rip); }
        if (!strcmp(cmd, "r")) {
            printf("RAX: 0x%llx | RBX: 0x%llx | RCX: 0x%llx\n", ctx.Rax, ctx.Rbx, ctx.Rcx);
            printf("RBP: 0x%llx | RSP: 0x%llx | RIP: 0x%llx\n", ctx.Rbp, ctx.Rsp, ctx.Rip);
        }
        if (!strcmp(cmd, "p")) {
            uint64_t ptr = g_dbinfo_addr;
            int found = 0;
            while (!found) {
                FuncEntry f;
                if (!ReadProcessMemory(hProc, (LPCVOID)ptr, &f, sizeof(f), NULL) || f.func_name_ptr == 0) break;
                if (ctx.Rip >= f.start_addr && ctx.Rip <= f.end_addr) {
                    uint64_t vptr = ptr + sizeof(f);
                    for (uint32_t i = 0; i < f.var_count; i++) {
                        VarEntry v; ReadProcessMemory(hProc, (LPCVOID)vptr, &v, sizeof(v), NULL);
                        char vn[64] = {0}; ReadProcessMemory(hProc, (LPCVOID)v.name_ptr, vn, 63, NULL);
                        if (!strcmp(vn, arg)) {
                            uint64_t addr = ctx.Rbp + v.offset;
                            if (v.type == 0) {
                                int val; ReadProcessMemory(hProc, (LPCVOID)addr, &val, 4, NULL);
                                printf(CLR_FUNC "%s" CLR_RESET " = %d\n", vn, val);
                            } else {
                                uint64_t sptr; ReadProcessMemory(hProc, (LPCVOID)addr, &sptr, 8, NULL);
                                char s[128] = {0}; ReadProcessMemory(hProc, (LPCVOID)sptr, s, 127, NULL);
                                printf(CLR_FUNC "%s" CLR_RESET " = \"%s\"\n", vn, s);
                            }
                            found = 1; break;
                        }
                        vptr += sizeof(v);
                    }
                }
                ptr += sizeof(f) + (f.var_count * sizeof(VarEntry));
                if (found) break;
            }
            if (!found) printf(CLR_ERR "[-] Переменная не найдена.\n" CLR_RESET);
        }
        if (!strcmp(cmd, "dis")) disassemble_at(hProc, ctx.Rip, 5);
        if (!strcmp(cmd, "q")) { TerminateProcess(hProc, 0); exit(0); }
        if (!strcmp(cmd, "h")) {
            printf("\nКоманды:\n  n   - Continue\n  s   - Step\n  bt  - Backtrace (Stack)\n"
                   "  p [v] - Print variable\n  r   - Registers\n  dis - Disassemble\n  q   - Quit\n");
        }
    }
}

void disassemble_at(HANDLE hProc, uint64_t addr, int inst_count) {
    csh handle; cs_insn *insn; uint8_t code[128];
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) return;
    SIZE_T br;
    if (ReadProcessMemory(hProc, (LPCVOID)addr, code, sizeof(code), &br)) {
        size_t count = cs_disasm(handle, code, br, addr, inst_count, &insn);
        for (size_t j = 0; j < count; j++) {
            printf("  " CLR_ADDR "0x%llx:" CLR_RESET "  %-8s %s\n", insn[j].address, insn[j].mnemonic, insn[j].op_str);
            if (!strcmp(insn[j].mnemonic, "ret")) break;
        }
        cs_free(insn, count);
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
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++)
        if (!strncmp((char*)s[i].Name, sectionName, 8)) { rva = s[i].VirtualAddress; break; }
    UnmapViewOfFile(p); CloseHandle(hMap); CloseHandle(hFile);
    return rva;
}
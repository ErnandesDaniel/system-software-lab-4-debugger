#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

// --- Структуры данных метаданных ---
typedef struct {
    uint64_t name_ptr;
    uint32_t type;
    int32_t offset;
} VarEntry;

// --- Глобальные переменные ---
uint64_t g_dbinfo_addr = 0;
uint64_t g_dbline_addr = 0;
uint64_t g_bp_addrs[100];
unsigned char g_orig_bytes[100];
int g_bp_count = 0;

const char* g_reg_names[] = {
    "RAX", "RDX", "RCX", "RBX", "RSI", "RDI", "RBP", "RSP",
    "R8",  "R9",  "R10", "R11", "R12", "R13", "R14", "R15", "RIP"
};

// --- Прототипы функций ---
uint64_t GetSectionRVA(const char* filename, const char* sectionName);
void handle_interactive_menu(HANDLE hProc, HANDLE hThread);
uint64_t get_reg_value(CONTEXT* ctx, int idx);

// ============================================================================
// MAIN
// ============================================================================
int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <program.exe> [line_number]\n", argv[0]);
        return 1;
    }
    const char* exe = argv[1];

    // Если указан 3-й аргумент, используем его как фильтр строки, иначе -1 (все)
    int target_line = (argc >= 3) ? atoi(argv[2]) : -1;

    uint64_t rva_info = GetSectionRVA(exe, ".dbinfo");
    uint64_t rva_line = GetSectionRVA(exe, ".dbline");

    if (!rva_info || !rva_line) {
        printf("[-] Error: Debug sections (.dbinfo/.dbline) not found in %s\n", exe);
        return 1;
    }

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    if (!CreateProcessA(exe, NULL, NULL, NULL, FALSE, DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &si, &pi)) {
        printf("[-] Error: Could not start process %s\n", exe);
        return 1;
    }

    DEBUG_EVENT de;
    int system_bp_done = 0;

    while (WaitForDebugEvent(&de, INFINITE)) {
        if (de.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT) {
            uint64_t base = (uint64_t)de.u.CreateProcessInfo.lpBaseOfImage;
            g_dbinfo_addr = base + rva_info;
            g_dbline_addr = base + rva_line;
        }
        else if (de.dwDebugEventCode == EXCEPTION_DEBUG_EVENT &&
                 de.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT) {

            if (!system_bp_done) {
                system_bp_done = 1;

                // Читаем адреса из .dbline (шаг 16 байт: 8 байт адрес + 8 байт номер строки)
                for (int i = 0; i < 100; i++) {
                    uint64_t addr_val = 0;
                    uint64_t line_val = 0;

                    ReadProcessMemory(pi.hProcess, (LPCVOID)(g_dbline_addr + (i * 16)), &addr_val, 8, NULL);
                    if (addr_val == 0) break;

                    ReadProcessMemory(pi.hProcess, (LPCVOID)(g_dbline_addr + (i * 16) + 8), &line_val, 8, NULL);

                    // Ставим брейкпоинт только если это нужная строка или если фильтр не задан
                    if (target_line == -1 || target_line == (int)line_val) {
                        g_bp_addrs[g_bp_count] = addr_val;
                        ReadProcessMemory(pi.hProcess, (LPVOID)addr_val, &g_orig_bytes[g_bp_count], 1, NULL);

                        unsigned char int3 = 0xCC;
                        WriteProcessMemory(pi.hProcess, (LPVOID)addr_val, &int3, 1, NULL);
                        g_bp_count++;
                    }
                }

                if (target_line != -1)
                    printf("[*] Single-step mode: stopping only at line %d\n", target_line);
                else
                    printf("[*] Loaded %d breakpoints.\n", g_bp_count);

                printf("[*] Commands: 'p <name>', 'r <num>', 'n', 'q'\n");
            } else {
                handle_interactive_menu(pi.hProcess, pi.hThread);

                CONTEXT ctx; ctx.ContextFlags = CONTEXT_FULL;
                GetThreadContext(pi.hThread, &ctx);
                ctx.Rip--;
                uint64_t f_addr = ctx.Rip;

                for(int i = 0; i < g_bp_count; i++) {
                    if (g_bp_addrs[i] == f_addr)
                        WriteProcessMemory(pi.hProcess, (LPVOID)f_addr, &g_orig_bytes[i], 1, NULL);
                }
                SetThreadContext(pi.hThread, &ctx);
            }
        }
        else if (de.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
            printf("[*] Process finished.\n");
            break;
        }
        ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
    }
    return 0;
}

// ============================================================================
// ИНТЕРАКТИВНОЕ МЕНЮ (Без изменений)
// ============================================================================
void handle_interactive_menu(HANDLE hProc, HANDLE hThread) {
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(hThread, &ctx);

    printf("\n>>> Breakpoint hit at 0x%llx\n", ctx.Rip - 1);

    char input[256];
    while (1) {
        printf("(dbg) ");
        if (!fgets(input, sizeof(input), stdin)) break;

        char cmd[16], arg[64];
        int count = sscanf(input, "%s %s", cmd, arg);
        if (count < 1) continue;

        if (strcmp(cmd, "n") == 0) break;
        else if (strcmp(cmd, "q") == 0) { TerminateProcess(hProc, 0); exit(0); }
        else if (strcmp(cmd, "r") == 0 && count == 2) {
            int reg_idx = atoi(arg);
            if (reg_idx >= 0 && reg_idx <= 16) {
                uint64_t val = get_reg_value(&ctx, reg_idx);
                printf("%s (reg %d) = 0x%llx\n", g_reg_names[reg_idx], reg_idx, val);
            }
        }
        else if (strcmp(cmd, "p") == 0 && count == 2) {
            uint32_t var_count;
            ReadProcessMemory(hProc, (LPCVOID)(g_dbinfo_addr + 24), &var_count, 4, NULL);
            uint64_t cur_var = g_dbinfo_addr + 28;
            int found = 0;

            for (uint32_t i = 0; i < var_count; i++) {
                VarEntry var;
                ReadProcessMemory(hProc, (LPCVOID)cur_var, &var, sizeof(VarEntry), NULL);
                char vname[64] = {0};
                ReadProcessMemory(hProc, (LPCVOID)var.name_ptr, vname, 63, NULL);

                if (strcmp(vname, arg) == 0) {
                    uint64_t val_addr = ctx.Rbp + var.offset;
                    if (var.type == 0) {
                        int val; ReadProcessMemory(hProc, (LPCVOID)val_addr, &val, 4, NULL);
                        printf("%s (int) = %d\n", vname, val);
                    } else {
                        uint64_t s_ptr; ReadProcessMemory(hProc, (LPCVOID)val_addr, &s_ptr, 8, NULL);
                        char s_val[128] = {0}; ReadProcessMemory(hProc, (LPCVOID)s_ptr, s_val, 127, NULL);
                        printf("%s (string) = \"%s\"\n", vname, s_val);
                    }
                    found = 1; break;
                }
                cur_var += sizeof(VarEntry);
            }
            if (!found) printf("Variable '%s' not found.\n", arg);
        }
        else if (strcmp(cmd, "help") == 0) printf("Commands: p <name>, r <0-16>, n, q\n");
    }
}

// ============================================================================
// ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ (Без изменений)
// ============================================================================
uint64_t get_reg_value(CONTEXT* ctx, int idx) {
    switch (idx) {
        case 0:  return ctx->Rax; case 1:  return ctx->Rdx;
        case 2:  return ctx->Rcx; case 3:  return ctx->Rbx;
        case 4:  return ctx->Rsi; case 5:  return ctx->Rdi;
        case 6:  return ctx->Rbp; case 7:  return ctx->Rsp;
        case 8:  return ctx->R8;  case 9:  return ctx->R9;
        case 10: return ctx->R10; case 11: return ctx->R11;
        case 12: return ctx->R12; case 13: return ctx->R13;
        case 14: return ctx->R14; case 15: return ctx->R15;
        case 16: return ctx->Rip;
        default: return 0;
    }
}

uint64_t GetSectionRVA(const char* filename, const char* sectionName) {
    HANDLE hFile = CreateFileA(filename, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (hFile == INVALID_HANDLE_VALUE) return 0;
    HANDLE hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    LPVOID pBase = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)pBase;
    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)pBase + dos->e_lfanew);
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    uint64_t rva = 0;
    for (int i = 0; i < nt->FileHeader.NumberOfSections; i++) {
        if (strncmp((char*)sec[i].Name, sectionName, 8) == 0) { rva = sec[i].VirtualAddress; break; }
    }
    UnmapViewOfFile(pBase); CloseHandle(hMapping); CloseHandle(hFile);
    return rva;
}
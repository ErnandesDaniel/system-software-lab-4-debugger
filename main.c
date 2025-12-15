#include <windows.h>
#include <stdio.h>
#include <stdint.h>

// --- Структуры данных ---
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

// --- Прототипы вспомогательных функций ---
uint64_t GetSectionRVA(const char* filename, const char* sectionName);
void print_vars(HANDLE hProc, HANDLE hThread);

// ============================================================================
// ГЛАВНАЯ ФУНКЦИЯ (MAIN)
// ============================================================================
int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: %s <program.exe>\n", argv[0]);
        return 1;
    }
    const char* exe = argv[1];

    // 1. Предварительный поиск смещений секций
    uint64_t rva_info = GetSectionRVA(exe, ".dbinfo");
    uint64_t rva_line = GetSectionRVA(exe, ".dbline");

    if (!rva_info || !rva_line) {
        printf("[-] Error: Debug sections not found in %s\n", exe);
        return 1;
    }

    // 2. Запуск процесса
    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi;
    if (!CreateProcessA(exe, NULL, NULL, NULL, FALSE, DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &si, &pi)) {
        printf("[-] Error: Could not start process.\n");
        return 1;
    }

    DEBUG_EVENT de;
    int system_bp_done = 0;

    while (WaitForDebugEvent(&de, INFINITE)) {
        if (de.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT) {
            // Вычисляем абсолютные адреса в памяти после загрузки процесса
            uint64_t base = (uint64_t)de.u.CreateProcessInfo.lpBaseOfImage;
            g_dbinfo_addr = base + rva_info;
            g_dbline_addr = base + rva_line;
        }
        else if (de.dwDebugEventCode == EXCEPTION_DEBUG_EVENT &&
                 de.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT) {

            if (!system_bp_done) {
                // Это первая остановка (System Breakpoint). Ставим наши ловушки.
                system_bp_done = 1;
                for (int i = 0; i < 100; i++) {
                    uint64_t target;
                    // Читаем адреса из таблицы .dbline (шаг 12 байт: 8 за адрес + 4 за номер строки)
                    ReadProcessMemory(pi.hProcess, (LPCVOID)(g_dbline_addr + (i * 12)), &target, 8, NULL);

                    if (target == 0) break; // Конец таблицы

                    g_bp_addrs[g_bp_count] = target;
                    ReadProcessMemory(pi.hProcess, (LPVOID)target, &g_orig_bytes[g_bp_count], 1, NULL);

                    unsigned char int3 = 0xCC; // Опкод брейкпоинта
                    WriteProcessMemory(pi.hProcess, (LPVOID)target, &int3, 1, NULL);
                    g_bp_count++;
                }
                printf("[*] Debugger ready. Loaded %d breakpoints from .dbline section.\n", g_bp_count);
            } else {
                // Наш брейкпоинт сработал!
                print_vars(pi.hProcess, pi.hThread);
                printf("Press Enter to continue...");
                getchar();

                // Восстановление оригинального байта для продолжения выполнения
                CONTEXT ctx;
                ctx.ContextFlags = CONTEXT_FULL;
                GetThreadContext(pi.hThread, &ctx);

                ctx.Rip--; // Откатываемся на начало инструкции
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
// ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ (РЕАЛИЗАЦИЯ)
// ============================================================================

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
        if (strncmp((char*)sec[i].Name, sectionName, 8) == 0) {
            rva = sec[i].VirtualAddress;
            break;
        }
    }
    UnmapViewOfFile(pBase); CloseHandle(hMapping); CloseHandle(hFile);
    return rva;
}

void print_vars(HANDLE hProc, HANDLE hThread) {
    CONTEXT ctx;
    ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(hThread, &ctx);

    if (ctx.Rbp <= 1) return; // Стек еще не готов

    uint32_t var_count;
    ReadProcessMemory(hProc, (LPCVOID)(g_dbinfo_addr + 24), &var_count, 4, NULL);

    printf("\n>>> BREAKPOINT HIT | RIP: 0x%llx | RBP: 0x%llx <<<", ctx.Rip - 1, ctx.Rbp);

    uint64_t cur_var = g_dbinfo_addr + 28;
    for (uint32_t i = 0; i < var_count; i++) {
        VarEntry var;
        ReadProcessMemory(hProc, (LPCVOID)cur_var, &var, sizeof(VarEntry), NULL);

        char name[64] = {0};
        ReadProcessMemory(hProc, (LPCVOID)var.name_ptr, name, 63, NULL);

        uint64_t val_addr = ctx.Rbp + var.offset;

        if (var.type == 0) { // int
            int val;
            ReadProcessMemory(hProc, (LPCVOID)val_addr, &val, 4, NULL);
            printf("\n  [INT]    %s = %d", name, val);
        } else { // string
            uint64_t s_ptr;
            ReadProcessMemory(hProc, (LPCVOID)val_addr, &s_ptr, 8, NULL);
            char s_val[128] = {0};
            ReadProcessMemory(hProc, (LPCVOID)s_ptr, s_val, 127, NULL);
            printf("\n  [STRING] %s = \"%s\"", name, s_val);
        }
        cur_var += sizeof(VarEntry);
    }
    printf("\n------------------------------------------------\n");
}
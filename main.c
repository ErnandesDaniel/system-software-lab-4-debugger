#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

typedef struct {
    uint64_t name_ptr;
    uint32_t type;
    int32_t offset;
} VarEntry;

uint64_t g_dbinfo_addr = 0;
uint64_t g_dbline_addr = 0;
uint64_t g_bp_addrs[100];
unsigned char g_orig_bytes[100];
int g_bp_count = 0;

// Прототипы
uint64_t GetSectionRVA(const char* filename, const char* sectionName);
void handle_interactive_menu(HANDLE hProc, HANDLE hThread);

int main(int argc, char* argv[]) {
    if (argc < 2) { printf("Usage: %s <file.exe>\n", argv[0]); return 1; }

    uint64_t rva_info = GetSectionRVA(argv[1], ".dbinfo");
    uint64_t rva_line = GetSectionRVA(argv[1], ".dbline");

    if (!rva_info || !rva_line) { printf("[-] Error: Debug sections not found.\n"); return 1; }

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
        }
        else if (de.dwDebugEventCode == EXCEPTION_DEBUG_EVENT &&
                 de.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT) {

            if (!system_bp_done) {
                system_bp_done = 1;
                for (int i = 0; i < 100; i++) {
                    uint64_t target;
                    ReadProcessMemory(pi.hProcess, (LPCVOID)(g_dbline_addr + (i * 12)), &target, 8, NULL);
                    if (target == 0) break;
                    g_bp_addrs[g_bp_count] = target;
                    ReadProcessMemory(pi.hProcess, (LPVOID)target, &g_orig_bytes[g_bp_count], 1, NULL);
                    unsigned char int3 = 0xCC;
                    WriteProcessMemory(pi.hProcess, (LPVOID)target, &int3, 1, NULL);
                    g_bp_count++;
                }
                printf("[*] Loaded %d breakpoints. Commands: 'p <name>', 'n', 'q', 'help'\n", g_bp_count);
            } else {
                // ПЕРЕХОД В ИНТЕРАКТИВНЫЙ РЕЖИМ
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
        else if (de.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) break;
        ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
    }
    return 0;
}

// --- Новая функция обработки команд ---
void handle_interactive_menu(HANDLE hProc, HANDLE hThread) {
    CONTEXT ctx; ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(hThread, &ctx);

    printf("\n>>> Paused at 0x%llx\n", ctx.Rip - 1);

    char input[256];
    while (1) {
        printf("(dbg) ");
        if (!fgets(input, sizeof(input), stdin)) break;

        char cmd[16], arg[64];
        int count = sscanf(input, "%s %s", cmd, arg);
        if (count < 1) continue;

        if (strcmp(cmd, "n") == 0) {
            break; // Следующий брейкпоинт
        }
        else if (strcmp(cmd, "q") == 0) {
            TerminateProcess(hProc, 0); exit(0);
        }
        else if (strcmp(cmd, "p") == 0 && count == 2) {
            // ПОИСК ПЕРЕМЕННОЙ ПО ИМЕНИ
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
                        printf("%s = %d\n", vname, val);
                    } else {
                        uint64_t s_ptr; ReadProcessMemory(hProc, (LPCVOID)val_addr, &s_ptr, 8, NULL);
                        char s_val[128] = {0}; ReadProcessMemory(hProc, (LPCVOID)s_ptr, s_val, 127, NULL);
                        printf("%s = \"%s\"\n", vname, s_val);
                    }
                    found = 1; break;
                }
                cur_var += sizeof(VarEntry);
            }
            if (!found) printf("No variable named '%s' found.\n", arg);
        }
        else if (strcmp(cmd, "help") == 0) {
            printf("Commands:\n  p <name> - print variable value\n  n        - go to next breakpoint\n  q        - quit\n");
        }
        else {
            printf("Unknown command. Type 'help' for list.\n");
        }
    }
}

// GetSectionRVA остается такой же...
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
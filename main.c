#include <windows.h>
#include <stdio.h>
#include <stdint.h>

typedef struct { uint64_t name_ptr; uint32_t type; int32_t offset; } VarEntry;

uint64_t g_dbinfo_addr = 0;
uint64_t g_dbline_addr = 0;
uint64_t g_bp_addrs[100];
unsigned char g_orig_bytes[100];
int g_bp_count = 0;

// Функция для поиска RVA (относительного адреса) секции по имени
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
    CONTEXT ctx; ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(hThread, &ctx);
    if (ctx.Rbp <= 1) return;

    uint32_t var_count;
    ReadProcessMemory(hProc, (LPCVOID)(g_dbinfo_addr + 24), &var_count, 4, NULL);

    printf("\n--- LINE HIT | RIP: 0x%llx | RBP: 0x%llx ---", ctx.Rip - 1, ctx.Rbp);
    uint64_t cur_var = g_dbinfo_addr + 28;
    for (uint32_t i = 0; i < var_count; i++) {
        VarEntry var;
        ReadProcessMemory(hProc, (LPCVOID)cur_var, &var, sizeof(VarEntry), NULL);
        char name[64] = {0};
        ReadProcessMemory(hProc, (LPCVOID)var.name_ptr, name, 63, NULL);

        uint64_t val_addr = ctx.Rbp + var.offset;
        if (var.type == 0) { // int
            int val; ReadProcessMemory(hProc, (LPCVOID)val_addr, &val, 4, NULL);
            printf("\n  %s = %d", name, val);
        } else { // string
            uint64_t s_ptr; ReadProcessMemory(hProc, (LPCVOID)val_addr, &s_ptr, 8, NULL);
            char s_val[128] = {0}; ReadProcessMemory(hProc, (LPCVOID)s_ptr, s_val, 127, NULL);
            printf("\n  %s = \"%s\"", name, s_val);
        }
        cur_var += sizeof(VarEntry);
    }
    printf("\n----------------------------------------------\n");
}

int main(int argc, char* argv[]) {
    if (argc < 2) return 1;
    const char* exe = argv[1];

    uint64_t rva_info = GetSectionRVA(exe, ".dbinfo");
    uint64_t rva_line = GetSectionRVA(exe, ".dbline");

    STARTUPINFOA si = { sizeof(si) }; PROCESS_INFORMATION pi;
    if (!CreateProcessA(exe, NULL, NULL, NULL, FALSE, DEBUG_ONLY_THIS_PROCESS, NULL, NULL, &si, &pi)) return 1;

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
                // Читаем адреса из .dbline и ставим брейкпоинты
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
                printf("[*] Loaded %d breakpoints from .dbline section.\n", g_bp_count);
            } else {
                print_vars(pi.hProcess, pi.hThread);
                printf("Press Enter..."); getchar();

                CONTEXT ctx; ctx.ContextFlags = CONTEXT_FULL;
                GetThreadContext(pi.hThread, &ctx);
                ctx.Rip--;
                uint64_t f_addr = ctx.Rip;
                for(int i=0; i<g_bp_count; i++) {
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
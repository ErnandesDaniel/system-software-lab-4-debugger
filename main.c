#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

// Структуры для парсинга
typedef struct {
    uint32_t offset;  // смещение от начала .text
    uint32_t line;
} DbLineEntry;

typedef struct {
    const char* name;
    uint32_t type;      // 0 = int, 1 = string
    int32_t rbp_offset;
} DbVar;

// Глобальные
HANDLE hProcess = NULL;
HANDLE hThread = NULL;
uint64_t image_base = 0;
uint64_t text_rva = 0;
uint64_t breakpoint_va = 0;
BYTE original_byte = 0;
DbVar locals[10];
int num_locals = 0;
char* dbstr_data = NULL;
size_t dbstr_size = 0;

// Прототипы
BOOL ReadSection(const char* filename, const char* name, void** data, DWORD* size);
uint64_t GetSectionRVA(const char* filename, const char* name);
void ParseDbInfo(const char* filename);
void ParseDbLineAndList(const char* filename);
BOOL SetBreakpoint(uint64_t va);
BOOL RemoveBreakpoint(uint64_t va);
void DebugLoop(uint64_t target_rva);

// =================================================
//                     main()
// =================================================
int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("Usage: debugger <exe_file>\n");
        return 1;
    }

    const char* exe = argv[1];

    // Найдём RVA секции .text
    text_rva = GetSectionRVA(exe, ".text");
    if (text_rva == 0) {
        printf("[-] Cannot find .text RVA\n");
        return 1;
    }

    // Загрузим имена переменных из .dbstr
    ReadSection(exe, ".dbstr", (void**)&dbstr_data, (DWORD*)&dbstr_size);

    // Прочитаем информацию о переменных
    ParseDbInfo(exe);

    // Покажем доступные строки и дадим выбрать
    ParseDbLineAndList(exe);

    return 0;
}

// =================================================
//              Вспомогательные функции
// =================================================

BOOL ReadSection(const char* filename, const char* name, void** data, DWORD* size) {
    FILE* f = fopen(filename, "rb");
    if (!f) return FALSE;

    IMAGE_DOS_HEADER dos;
    fread(&dos, sizeof(dos), 1, f);
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) { fclose(f); return FALSE; }

    fseek(f, dos.e_lfanew, SEEK_SET);
    IMAGE_NT_HEADERS64 nt;
    fread(&nt, sizeof(nt), 1, f);
    if (nt.Signature != IMAGE_NT_SIGNATURE) { fclose(f); return FALSE; }

    for (int i = 0; i < nt.FileHeader.NumberOfSections; ++i) {
        IMAGE_SECTION_HEADER sec;
        fread(&sec, sizeof(sec), 1, f);
        if (strncmp((char*)sec.Name, name, 8) == 0) {
            *size = sec.SizeOfRawData ? sec.SizeOfRawData : sec.Misc.VirtualSize;
            *data = malloc(*size);
            fseek(f, sec.PointerToRawData, SEEK_SET);
            fread(*data, 1, *size, f);
            fclose(f);
            return TRUE;
        }
    }
    fclose(f);
    return FALSE;
}

uint64_t GetSectionRVA(const char* filename, const char* name) {
    FILE* f = fopen(filename, "rb");
    if (!f) return 0;

    IMAGE_DOS_HEADER dos;
    fread(&dos, sizeof(dos), 1, f);
    if (dos.e_magic != IMAGE_DOS_SIGNATURE) { fclose(f); return 0; }

    fseek(f, dos.e_lfanew, SEEK_SET);
    IMAGE_NT_HEADERS64 nt;
    fread(&nt, sizeof(nt), 1, f);
    if (nt.Signature != IMAGE_NT_SIGNATURE) { fclose(f); return 0; }

    for (int i = 0; i < nt.FileHeader.NumberOfSections; ++i) {
        IMAGE_SECTION_HEADER sec;
        fread(&sec, sizeof(sec), 1, f);
        if (strncmp((char*)sec.Name, name, 8) == 0) {
            fclose(f);
            return sec.VirtualAddress;
        }
    }
    fclose(f);
    return 0;
}

void ParseDbInfo(const char* filename) {
    void* data; DWORD size;
    if (!ReadSection(filename, ".dbinfo", &data, &size)) return;

    uint8_t* p = (uint8_t*)data;
    p += 8; // пропустить имя функции (8 байт)
    uint32_t params = *(uint32_t*)p; p += 4;
    num_locals = *(uint32_t*)p; p += 4;

    if (num_locals > 10) num_locals = 10;

    for (int i = 0; i < num_locals; ++i) {
        uint64_t name_off = *(uint64_t*)p; p += 8;
        locals[i].type = *(uint32_t*)p; p += 4;
        locals[i].rbp_offset = *(int32_t*)p; p += 4;
        locals[i].name = (dbstr_data && name_off < dbstr_size) ? (dbstr_data + name_off) : "unknown";
    }

    free(data);
}

void ParseDbLineAndList(const char* filename) {
    void* data; DWORD size;
    if (!ReadSection(filename, ".dbline", &data, &size)) {
        printf("[-] No .dbline found\n");
        return;
    }

    printf("\n=== Available breakpoints ===\n");
    DbLineEntry* entries = (DbLineEntry*)data;
    int count = 0;
    while (entries[count].offset != 0 || entries[count].line != 0) {
        uint64_t rva = text_rva + entries[count].offset;
        printf("  %d: line %u (RVA 0x%llx)\n", count + 1, entries[count].line, rva);
        count++;
    }

    if (count == 0) {
        printf("  No breakpoints available.\n");
        free(data);
        return;
    }

    printf("\nChoose line number to break at (1-%d): ", count);
    int choice;
    if (scanf("%d", &choice) != 1 || choice < 1 || choice > count) {
        printf("Invalid choice.\n");
        free(data);
        return;
    }

    uint64_t target_rva = text_rva + entries[choice - 1].offset;
    free(data);

    // Запускаем процесс и отлаживаем
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);

    if (!CreateProcessA(filename, NULL, NULL, NULL, FALSE,
                        DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS,
                        NULL, NULL, &si, &pi)) {
        printf("CreateProcess failed\n");
        return;
    }

    hProcess = pi.hProcess;
    hThread = pi.hThread;
    image_base = (uint64_t) /* получим ниже */ 0;

    // Запускаем отладочный цикл
    DebugLoop(target_rva);
}

BOOL SetBreakpoint(uint64_t va) {
    if (!ReadProcessMemory(hProcess, (void*)va, &original_byte, 1, NULL)) return FALSE;
    BYTE int3 = 0xCC;
    return WriteProcessMemory(hProcess, (void*)va, &int3, 1, NULL);
}

BOOL RemoveBreakpoint(uint64_t va) {
    return WriteProcessMemory(hProcess, (void*)va, &original_byte, 1, NULL);
}

void DebugLoop(uint64_t target_rva) {
    DEBUG_EVENT de;
    BOOL hit = FALSE;

    while (WaitForDebugEvent(&de, INFINITE)) {
        if (de.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT) {
            image_base = (uint64_t)de.u.CreateProcessInfo.lpBaseOfImage;
            breakpoint_va = image_base + target_rva;
            printf("\n[*] Process loaded. Image base = 0x%llx\n", image_base);
            printf("[*] Setting breakpoint at VA = 0x%llx\n", breakpoint_va);
            if (!SetBreakpoint(breakpoint_va)) {
                printf("[-] Failed to set breakpoint\n");
                break;
            }
        }

        if (de.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
            if (de.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT) {
                CONTEXT ctx;
                ctx.ContextFlags = CONTEXT_FULL;
                if (GetThreadContext(hThread, &ctx)) {
                    if (ctx.Rip == breakpoint_va + 1) { // после int3
                        printf("\n[!] HIT BREAKPOINT\n");
                        RemoveBreakpoint(breakpoint_va);
                        ctx.Rip = breakpoint_va;
                        SetThreadContext(hThread, &ctx);

                        // Single-step
                        ctx.ContextFlags = CONTEXT_FULL;
                        ctx.EFlags |= 0x100;
                        SetThreadContext(hThread, &ctx);
                        hit = TRUE;
                    } else if (hit && de.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_SINGLE_STEP) {
                        GetThreadContext(hThread, &ctx);
                        uint64_t rbp = ctx.Rbp;

                        printf("\n>>> Local variables:\n");
                        for (int i = 0; i < num_locals; ++i) {
                            if (locals[i].type == 0) { // int
                                int val;
                                if (ReadProcessMemory(hProcess, (void*)(rbp + locals[i].rbp_offset), &val, sizeof(val), NULL)) {
                                    printf("    %s = %d\n", locals[i].name, val);
                                }
                            } else if (locals[i].type == 1) { // string
                                char* ptr;
                                if (ReadProcessMemory(hProcess, (void*)(rbp + locals[i].rbp_offset), &ptr, sizeof(ptr), NULL) && ptr) {
                                    char buf[256] = {0};
                                    if (ReadProcessMemory(hProcess, ptr, buf, sizeof(buf) - 1, NULL)) {
                                        printf("    %s = \"%s\"\n", locals[i].name, buf);
                                    }
                                }
                            }
                        }

                        printf("\n[!] Press Enter to continue execution...\n");
                        getchar();
                        hit = FALSE;
                    }
                }
            }
        }

        if (de.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
            printf("\n[*] Process exited (code: %lu)\n", de.u.ExitProcess.dwExitCode);
            break;
        }

        ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
    }
}
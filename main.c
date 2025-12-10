#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

// ========== СТРУКТУРЫ ==========

typedef struct {
    uint64_t va_on_disk;   // VA метки в EXE на диске
    int line_number;
    uint64_t runtime_va;   // VA в памяти при запуске
} DebugLineEntry;

typedef struct {
    const char* name;
    int type;              // 0 = int, 1 = string (указатель)
    int32_t rbp_offset;
} DebugVar;

typedef struct {
    uint64_t disk_image_base;
    DebugLineEntry* lines;
    size_t num_lines;
    DebugVar* vars;
    size_t num_vars;
    LPVOID mapped_file;
    HANDLE hFileMap;
    HANDLE hFile;
} DebugInfo;

// ========== ОБЪЯВЛЕНИЯ ФУНКЦИЙ ==========

static PIMAGE_SECTION_HEADER GetSectionHeader(PIMAGE_NT_HEADERS nt, const char* name);
static DebugInfo* ParseDebugInfoFromFile(const char* exe_path);
static void FreeDebugInfo(DebugInfo* di);
static void ResolveRuntimeAddresses(DebugInfo* di, uint64_t runtime_base);
static BOOL SetBreakpoint(HANDLE hProcess, uint64_t va);
static void ReadVariable(HANDLE hProcess, DebugInfo* di, const char* var_name, uint64_t rbp);
static uint64_t FindNextLine(DebugInfo* di, uint64_t current_rip);

// ========== РЕАЛИЗАЦИЯ ==========

static PIMAGE_SECTION_HEADER GetSectionHeader(PIMAGE_NT_HEADERS nt, const char* name) {
    PIMAGE_SECTION_HEADER sec = IMAGE_FIRST_SECTION(nt);
    for (WORD i = 0; i < nt->FileHeader.NumberOfSections; i++, sec++) {
        if (strncmp((char*)sec->Name, name, IMAGE_SIZEOF_SHORT_NAME) == 0)
            return sec;
    }
    return NULL;
}

static DebugInfo* ParseDebugInfoFromFile(const char* exe_path) {
    DebugInfo* di = (DebugInfo*)calloc(1, sizeof(DebugInfo));
    if (!di) return NULL;

    di->hFile = CreateFileA(exe_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    if (di->hFile == INVALID_HANDLE_VALUE) goto fail;

    di->hFileMap = CreateFileMappingA(di->hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    if (!di->hFileMap) goto fail;

    di->mapped_file = MapViewOfFile(di->hFileMap, FILE_MAP_READ, 0, 0, 0);
    if (!di->mapped_file) goto fail;

    PIMAGE_DOS_HEADER dos = (PIMAGE_DOS_HEADER)di->mapped_file;
    if (dos->e_magic != IMAGE_DOS_SIGNATURE) goto fail;

    PIMAGE_NT_HEADERS nt = (PIMAGE_NT_HEADERS)((BYTE*)di->mapped_file + dos->e_lfanew);
    if (nt->Signature != IMAGE_NT_SIGNATURE) goto fail;

    di->disk_image_base = nt->OptionalHeader.ImageBase;

    // --- .dbline ---
    PIMAGE_SECTION_HEADER sec_line = GetSectionHeader(nt, ".dbline");
    if (sec_line && sec_line->SizeOfRawData > 0) {
        uint8_t* p = (uint8_t*)di->mapped_file + sec_line->PointerToRawData;
        size_t max_records = sec_line->SizeOfRawData / 12;

        size_t actual_count = 0;
        for (size_t i = 0; i < max_records; i++) {
            if (p + 12 > (uint8_t*)di->mapped_file + sec_line->PointerToRawData + sec_line->SizeOfRawData) {
                break;
            }
            uint64_t va = *(uint64_t*)p;
            uint32_t line = *(uint32_t*)(p + 8);
            if (va == 0 && line == 0) {
                break;
            }
            actual_count++;
            p += 12;
        }

        if (actual_count > 0) {
            di->num_lines = actual_count;
            di->lines = (DebugLineEntry*)calloc(di->num_lines, sizeof(DebugLineEntry));

            p = (uint8_t*)di->mapped_file + sec_line->PointerToRawData;
            for (size_t i = 0; i < di->num_lines; i++) {
                di->lines[i].va_on_disk = *(uint64_t*)p; p += 8;
                di->lines[i].line_number = *(uint32_t*)p; p += 4;
            }
        }
    }

    // --- .dbinfo ---
    PIMAGE_SECTION_HEADER sec_info = GetSectionHeader(nt, ".dbinfo");
    PIMAGE_SECTION_HEADER sec_str = GetSectionHeader(nt, ".dbstr");

    if (sec_info && sec_info->SizeOfRawData >= 36 + 24) { // 36 + 2*(8+4+4)
        uint8_t* p = (uint8_t*)di->mapped_file + sec_info->PointerToRawData;
        p += 36; // пропускаем заголовок функции

        di->num_vars = 2;
        di->vars = (DebugVar*)calloc(di->num_vars, sizeof(DebugVar));

        // Первая переменная: s
        uint64_t name_ptr_s = *(uint64_t*)p; p += 8;
        uint32_t type_s = *(uint32_t*)p; p += 4;
        int32_t offset_s = *(int32_t*)p; p += 4;

        // Вторая переменная: c
        uint64_t name_ptr_c = *(uint64_t*)p; p += 8;
        uint32_t type_c = *(uint32_t*)p; p += 4;
        int32_t offset_c = *(int32_t*)p; p += 4;

        // Обработка первой переменной
        if (sec_str) {
            uint64_t name_rva = name_ptr_s - di->disk_image_base;
            if (name_rva >= sec_str->VirtualAddress &&
                name_rva < sec_str->VirtualAddress + sec_str->SizeOfRawData) {
                uint64_t offset_in_section = name_rva - sec_str->VirtualAddress;
                const char* name_str = (const char*)di->mapped_file +
                                     sec_str->PointerToRawData + offset_in_section;
                di->vars[0].name = name_str;
            } else {
                di->vars[0].name = "s";
            }
        } else {
            di->vars[0].name = "s";
        }
        di->vars[0].type = type_s;
        di->vars[0].rbp_offset = offset_s;

        // Обработка второй переменной
        if (sec_str) {
            uint64_t name_rva = name_ptr_c - di->disk_image_base;
            if (name_rva >= sec_str->VirtualAddress &&
                name_rva < sec_str->VirtualAddress + sec_str->SizeOfRawData) {
                uint64_t offset_in_section = name_rva - sec_str->VirtualAddress;
                const char* name_str = (const char*)di->mapped_file +
                                     sec_str->PointerToRawData + offset_in_section;
                di->vars[1].name = name_str;
            } else {
                di->vars[1].name = "c";
            }
        } else {
            di->vars[1].name = "c";
        }
        di->vars[1].type = type_c;
        di->vars[1].rbp_offset = offset_c;

        // Отладочный вывод
        printf("DEBUG: Parsed variables:\n");
        printf("  s: name='%s', type=%u, offset=%d\n",
               di->vars[0].name, di->vars[0].type, di->vars[0].rbp_offset);
        printf("  c: name='%s', type=%u, offset=%d\n",
               di->vars[1].name, di->vars[1].type, di->vars[1].rbp_offset);
    }

    return di;

fail:
    FreeDebugInfo(di);
    return NULL;
}

static void FreeDebugInfo(DebugInfo* di) {
    if (!di) return;
    if (di->mapped_file) UnmapViewOfFile(di->mapped_file);
    if (di->hFileMap) CloseHandle(di->hFileMap);
    if (di->hFile != INVALID_HANDLE_VALUE) CloseHandle(di->hFile);
    free(di->lines);
    free(di->vars);
    free(di);
}

static void ResolveRuntimeAddresses(DebugInfo* di, uint64_t runtime_base) {
    for (size_t i = 0; i < di->num_lines; i++) {
        uint64_t rva = di->lines[i].va_on_disk - di->disk_image_base;
        di->lines[i].runtime_va = runtime_base + rva;
    }
}

static BOOL SetBreakpoint(HANDLE hProcess, uint64_t va) {
    BYTE old_byte;
    SIZE_T bytes_read;
    if (!ReadProcessMemory(hProcess, (LPCVOID)va, &old_byte, 1, &bytes_read))
        return FALSE;
    if (old_byte == 0xCC)
        return TRUE;
    BYTE int3 = 0xCC;
    return WriteProcessMemory(hProcess, (LPVOID)va, &int3, 1, NULL);
}

static void ReadVariable(HANDLE hProcess, DebugInfo* di, const char* var_name, uint64_t rbp) {
    DebugVar* v = NULL;
    for (size_t i = 0; i < di->num_vars; i++) {
        if (strcmp(di->vars[i].name, var_name) == 0) {
            v = &di->vars[i];
            break;
        }
    }
    if (!v) {
        printf("Unknown variable '%s'\n", var_name);
        return;
    }

    uint64_t addr = rbp + v->rbp_offset;
    if (v->type == 0) { // int (32-bit)
        int32_t val;
        SIZE_T read;
        if (ReadProcessMemory(hProcess, (LPCVOID)addr, &val, sizeof(val), &read)) {
            printf("%s = %d\n", var_name, val);
        } else {
            printf("Failed to read %s\n", var_name);
        }
    } else if (v->type == 1) { // string
        uint64_t ptr;
        SIZE_T read;
        if (ReadProcessMemory(hProcess, (LPCVOID)addr, &ptr, sizeof(ptr), &read)) {
            if (ptr == 0) {
                printf("%s = NULL\n", var_name);
            } else {
                char buf[256] = {0};
                ReadProcessMemory(hProcess, (LPCVOID)ptr, buf, sizeof(buf) - 1, &read);
                printf("%s = \"%s\"\n", var_name, buf);
            }
        } else {
            printf("Failed to read pointer for %s\n", var_name);
        }
    }
}

static uint64_t FindNextLine(DebugInfo* di, uint64_t current_rip) {
    uint64_t next_va = 0;
    for (size_t i = 0; i < di->num_lines; i++) {
        if (di->lines[i].runtime_va > current_rip) {
            if (next_va == 0 || di->lines[i].runtime_va < next_va) {
                next_va = di->lines[i].runtime_va;
            }
        }
    }
    return next_va;
}

// ========== MAIN ==========

int main(int argc, char* argv[]) {
    if (argc < 2) {
        printf("Usage: debugger <path_to_main.exe>\n");
        return 1;
    }

    const char* target = argv[1];
    DebugInfo* di = ParseDebugInfoFromFile(target);
    if (!di) {
        printf("Failed to parse debug info from %s\n", target);
        return 1;
    }

    printf("[*] Parsed %zu debug lines\n", di->num_lines);
    for (size_t i = 0; i < di->num_lines; i++) {
        printf("  line %d @ 0x%llx (disk VA)\n", di->lines[i].line_number, (unsigned long long)di->lines[i].va_on_disk);
    }

    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);

    char cmd_line[MAX_PATH];
    snprintf(cmd_line, sizeof(cmd_line), "\"%s\"", target);

    if (!CreateProcessA(NULL, cmd_line, NULL, NULL, FALSE,
                        DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS,
                        NULL, NULL, &si, &pi)) {
        printf("CreateProcess failed: %lu\n", GetLastError());
        FreeDebugInfo(di);
        return 1;
    }

    printf("[*] Process started, PID=%lu\n", pi.dwProcessId);

    uint64_t runtime_base = 0;
    BOOL is_running = TRUE;
    BOOL hit_initial_break = FALSE;
    uint64_t current_rip = 0;
    uint64_t current_rbp = 0;

    DEBUG_EVENT de;
    while (is_running) {
        if (!WaitForDebugEvent(&de, INFINITE)) break;

        DWORD continue_status = DBG_CONTINUE;

        switch (de.dwDebugEventCode) {
            case CREATE_PROCESS_DEBUG_EVENT: {
                runtime_base = (uint64_t)de.u.CreateProcessInfo.lpBaseOfImage;
                printf("[*] Image loaded at 0x%llx\n", (unsigned long long)runtime_base);
                ResolveRuntimeAddresses(di, runtime_base);
                if (di->num_lines > 0) {
                    SetBreakpoint(pi.hProcess, di->lines[0].runtime_va);
                    printf("[*] Breakpoint set at line %d\n", di->lines[0].line_number);
                }
                CloseHandle(de.u.CreateProcessInfo.hFile);
                break;
            }

            case EXCEPTION_DEBUG_EVENT: {
                DWORD code = de.u.Exception.ExceptionRecord.ExceptionCode;
                uint64_t fault_addr = (uint64_t)de.u.Exception.ExceptionRecord.ExceptionAddress;

                if (code == EXCEPTION_BREAKPOINT) {
                    if (!hit_initial_break) {
                        hit_initial_break = TRUE;
                        break;
                    }

                    int current_line = -1;
                    for (size_t i = 0; i < di->num_lines; i++) {
                        if (di->lines[i].runtime_va == fault_addr) {
                            current_line = di->lines[i].line_number;
                            break;
                        }
                    }

                    printf("\n>>> Stopped at line %d (0x%llx)\n", current_line, (unsigned long long)fault_addr);

                    CONTEXT ctx = {0};
                    ctx.ContextFlags = CONTEXT_CONTROL | CONTEXT_INTEGER;
                    if (GetThreadContext(pi.hThread, &ctx)) {
                        current_rip = ctx.Rip;
                        current_rbp = ctx.Rbp;
                    }

                    char cmd[256];
                    while (1) {
                        printf("(dbg) ");
                        if (!fgets(cmd, sizeof(cmd), stdin)) break;
                        cmd[strcspn(cmd, "\r\n")] = 0;

                        if (strcmp(cmd, "quit") == 0) {
                            is_running = FALSE;
                            break;
                        } else if (strcmp(cmd, "step") == 0) {
                            uint64_t next = FindNextLine(di, fault_addr);
                            if (next) {
                                SetBreakpoint(pi.hProcess, next);
                                printf("Stepping to next line...\n");
                            } else {
                                printf("No next line found.\n");
                            }
                            break;
                        } else if (strncmp(cmd, "print ", 6) == 0) {
                            char* var = cmd + 6;
                            if (current_rbp) {
                                ReadVariable(pi.hProcess, di, var, current_rbp);
                            } else {
                                printf("RBP not available\n");
                            }
                        } else if (strcmp(cmd, "regs") == 0) {
                            printf("RIP=0x%llx, RBP=0x%llx\n", (unsigned long long)current_rip, (unsigned long long)current_rbp);
                        } else {
                            printf("Commands: step, print <var>, regs, quit\n");
                        }
                    }
                } else {
                    printf("Exception 0x%lx at 0x%p\n", code, de.u.Exception.ExceptionRecord.ExceptionAddress);
                    is_running = FALSE;
                }
                break;
            }

            case EXIT_PROCESS_DEBUG_EVENT:
                printf("\n[*] Process exited with code %lu\n", de.u.ExitProcess.dwExitCode);
                is_running = FALSE;
                break;

            default:
                break;
        }

        if (!is_running) break;
        ContinueDebugEvent(de.dwProcessId, de.dwThreadId, continue_status);
    }

    CloseHandle(pi.hThread);
    CloseHandle(pi.hProcess);
    FreeDebugInfo(di);
    return 0;
}
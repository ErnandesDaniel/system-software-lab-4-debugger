#define _CRT_SECURE_NO_WARNINGS
#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>

typedef struct {
    uint32_t offset;     // смещение от начала .text
    uint32_t src_line;   // номер строки в исходном коде
} DbgLine;

// Глобальные
HANDLE hProcess = NULL;
HANDLE hThread = NULL;
uint64_t image_base = 0;
uint64_t text_rva = 0;
uint64_t target_breakpoint_va = 0;
BYTE original_byte = 0;
uint32_t target_offset = 0;
uint32_t target_line = 0;
BOOL first_breakpoint = TRUE;

// Прототипы
BOOL ReadSection(const char* filename, const char* name, void** data, DWORD* size);
uint64_t GetSectionRVA(const char* filename, const char* name);

// =================================================
//                     main()
// =================================================
int main(int argc, char* argv[]) {
    if (argc != 2) {
        printf("Usage: debugger <exe_file>\n");
        return 1;
    }

    const char* exe = argv[1];

    // --- 1. Получаем RVA секции .text ---
    text_rva = GetSectionRVA(exe, ".text");
    if (text_rva == 0) {
        printf("[-] Cannot find .text RVA\n");
        return 1;
    }

    // --- 2. Читаем .dbline ---
    void* dbline_data = NULL;
    DWORD dbline_size = 0;
    if (!ReadSection(exe, ".dbline", &dbline_data, &dbline_size)) {
        printf("[-] Cannot read .dbline\n");
        return 1;
    }

    // --- 3. Показываем строки ---
    printf("=== Available source lines ===\n");
    DbgLine* lines = (DbgLine*)dbline_data;
    int count = 0;
    while (lines[count].src_line != 0) {
        printf("  %d: line %u\n", count + 1, lines[count].src_line);
        count++;
    }

    if (count == 0) {
        printf("No source lines found.\n");
        free(dbline_data);
        return 1;
    }

    // --- 4. Выбор строки ---
    printf("\nChoose source line to break at: ");
    if (scanf("%u", &target_line) != 1) {
        printf("Invalid input.\n");
        free(dbline_data);
        return 1;
    }

    target_offset = 0;
    for (int i = 0; i < count; i++) {
        if (lines[i].src_line == target_line) {
            target_offset = lines[i].offset;
            break;
        }
    }
    free(dbline_data);

    if (target_offset == 0) {
        printf("Line %u not found.\n", target_line);
        return 1;
    }

    printf("[*] Will break at source line %u (offset 0x%x from .text)\n", target_line, target_offset);

    // --- 5. Запуск процесса ---
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);
    if (!CreateProcessA(exe, NULL, NULL, NULL, FALSE,
                        DEBUG_PROCESS | DEBUG_ONLY_THIS_PROCESS,
                        NULL, NULL, &si, &pi)) {
        printf("CreateProcess failed (%lu)\n", GetLastError());
        return 1;
    }

    hProcess = pi.hProcess;
    hThread = pi.hThread;

    // --- 6. Отладочный цикл ---
    DEBUG_EVENT de;
    while (WaitForDebugEvent(&de, INFINITE)) {
        if (de.dwDebugEventCode == CREATE_PROCESS_DEBUG_EVENT) {
            image_base = (uint64_t)de.u.CreateProcessInfo.lpBaseOfImage;
            printf("[*] Image base = 0x%llx\n", image_base);
            target_breakpoint_va = image_base + text_rva + target_offset;
        }

        if (de.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
            if (de.u.Exception.ExceptionRecord.ExceptionCode == EXCEPTION_BREAKPOINT) {
                if (first_breakpoint) {
                    // Это int3 в начале main
                    printf("[*] Hit initial breakpoint in main\n");
                    first_breakpoint = FALSE;

                    // Устанавливаем breakpoint по выбранной строке
                    if (ReadProcessMemory(hProcess, (void*)target_breakpoint_va, &original_byte, 1, NULL)) {
                        BYTE int3 = 0xCC;
                        if (WriteProcessMemory(hProcess, (void*)target_breakpoint_va, &int3, 1, NULL)) {
                            printf("[*] Breakpoint set at VA 0x%llx\n", target_breakpoint_va);
                        } else {
                            printf("[-] Failed to write breakpoint\n");
                        }
                    } else {
                        printf("[-] Failed to read original byte at target\n");
                    }

                    // Продолжаем выполнение (первый int3 пропускаем)
                    ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
                } else {
                    // Это наш целевой breakpoint
                    CONTEXT ctx;
                    ctx.ContextFlags = CONTEXT_FULL;
                    if (GetThreadContext(hThread, &ctx)) {
                        printf("\n[!] HIT BREAKPOINT at source line %u\n", target_line);
                        printf("RBP = 0x%llx\n", ctx.Rbp);

                        // Читаем .dbstr и .dbinfo
                        void* dbstr_data = NULL, *dbinfo_data = NULL;
                        DWORD dbstr_size = 0, dbinfo_size = 0;
                        ReadSection(exe, ".dbstr", &dbstr_data, &dbstr_size);
                        ReadSection(exe, ".dbinfo", &dbinfo_data, &dbinfo_size);

                        if (dbinfo_data && dbinfo_size >= 24) {
                            uint8_t* p = (uint8_t*)dbinfo_data;
                            p += 8; // пропустить имя функции
                            p += 8; // пропустить params (4) + locals (4)

                            // Переменная s
                            uint64_t name_off = *(uint64_t*)p; p += 8;
                            uint32_t type = *(uint32_t*)p; p += 4;
                            int32_t offset = *(int32_t*)p; p += 4;

                            const char* name = "s";
                            if (dbstr_data && name_off < dbstr_size) {
                                name = (const char*)((uint8_t*)dbstr_data + name_off);
                            }

                            if (type == 1) { // string
                                char* ptr = NULL;
                                ReadProcessMemory(hProcess, (void*)(ctx.Rbp + offset), &ptr, 8, NULL);
                                if (ptr) {
                                    char buf[256] = {0};
                                    ReadProcessMemory(hProcess, ptr, buf, 255, NULL);
                                    printf("    %s = \"%s\"\n", name, buf);
                                }
                            }

                            // Переменная c
                            name_off = *(uint64_t*)p; p += 8;
                            type = *(uint32_t*)p; p += 4;
                            offset = *(int32_t*)p; p += 4;

                            name = "c";
                            if (dbstr_data && name_off < dbstr_size) {
                                name = (const char*)((uint8_t*)dbstr_data + name_off);
                            }

                            if (type == 0) { // int
                                int val = 0;
                                ReadProcessMemory(hProcess, (void*)(ctx.Rbp + offset), &val, 4, NULL);
                                printf("    %s = %d\n", name, val);
                            }
                        }

                        if (dbstr_data) free(dbstr_data);
                        if (dbinfo_data) free(dbinfo_data);

                        printf("\n[!] Press Enter to continue...\n");
                        getchar();

                        // Восстанавливаем оригинальную инструкцию
                        WriteProcessMemory(hProcess, (void*)target_breakpoint_va, &original_byte, 1, NULL);
                        // Корректируем RIP, чтобы выполнить её
                        ctx.Rip = target_breakpoint_va;
                        SetThreadContext(hThread, &ctx);
                    }

                    ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
                }
            } else {
                ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
            }
        } else if (de.dwDebugEventCode == EXIT_PROCESS_DEBUG_EVENT) {
            printf("\n[*] Process exited (code: %lu)\n", de.u.ExitProcess.dwExitCode);
            break;
        } else {
            ContinueDebugEvent(de.dwProcessId, de.dwThreadId, DBG_CONTINUE);
        }
    }

    return 0;
}

// =================================================
//              Вспомогательные функции
// =================================================

BOOL ReadSection(const char* filename, const char* name, void** data, DWORD* size) {
    FILE* f = fopen(filename, "rb");
    if (!f) return FALSE;

    IMAGE_DOS_HEADER dos;
    if (fread(&dos, sizeof(dos), 1, f) != 1 || dos.e_magic != 0x5A4D) {
        fclose(f); return FALSE;
    }

    fseek(f, dos.e_lfanew, SEEK_SET);
    IMAGE_NT_HEADERS64 nt;
    if (fread(&nt, sizeof(nt), 1, f) != 1 || nt.Signature != 0x4550) {
        fclose(f); return FALSE;
    }

    for (int i = 0; i < nt.FileHeader.NumberOfSections; ++i) {
        IMAGE_SECTION_HEADER sec;
        if (fread(&sec, sizeof(sec), 1, f) != 1) break;
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
    if (fread(&dos, sizeof(dos), 1, f) != 1 || dos.e_magic != 0x5A4D) {
        fclose(f); return 0;
    }

    fseek(f, dos.e_lfanew, SEEK_SET);
    IMAGE_NT_HEADERS64 nt;
    if (fread(&nt, sizeof(nt), 1, f) != 1 || nt.Signature != 0x4550) {
        fclose(f); return 0;
    }

    for (int i = 0; i < nt.FileHeader.NumberOfSections; ++i) {
        IMAGE_SECTION_HEADER sec;
        if (fread(&sec, sizeof(sec), 1, f) != 1) break;
        if (strncmp((char*)sec.Name, name, 8) == 0) {
            fclose(f);
            return sec.VirtualAddress;
        }
    }
    fclose(f);
    return 0;
}
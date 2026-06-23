# 0adC2 — TODO / Roadmap

## Legend
- `[x]` done
- `[~]` partial / needs improvement
- `[ ]` to do
- `[!]` high priority (detection / stability risk if left open)

---

## Protocol — 0AD fidelity

| # | Item | Status |
|---|------|--------|
| 1 | `NMT_END_COMMAND_BATCH` (type 26) every ~200ms | `[x]` |
| 2 | Sender name set in NMT_CHAT (was empty `""`) | `[x]` |
| 3 | GUID in `NMT_AUTHENTICATE` (was `wcstr("")`) | `[x]` |
| 4 | `NMT_SYNC_CHECK` (type 27) replied with turn + pseudo-stable hash | `[x]` |
| 5 | ZW encoding (U+200B/C/D) → replaced by noise word index | `[x]` |
| 26 | Reply to server `NMT_PING` with a realistic RTT (currently silently ignored) | `[x]` |
| 30 | `NMT_SYNC_CHECK` drifting hash: constant hash detectable across sessions | `[!]` |
| 29 | `NMT_END_COMMAND_BATCH` jitter: replace fixed ±10ms with log-normal distribution | `[~]` |
| 24 | Capture real 0AD client with Wireshark — map all NMT types sent during active phase | `[ ]` |
| 25 | Implement `NMT_OBSERVER_SYNCED`, `NMT_CLIENT_PERFORMANCE` (sent by real spectators) | `[ ]` |
| 27 | Implement `NMT_GAME_LOAD_PROGRESS` (type 22) during map loading | `[ ]` |
| 28 | Fake NMT_CHAT volume correlated to simulated game activity (~50–200 msg/h) | `[ ]` |
| 42 | **Traffic simulation** — emit realistic non-chat NMT packets (NMT_GAME_STATE_SYNC, NMT_OBSERVED_GAME_COMMAND, resource drops, unit moves) to look like a real spectator, not a chat-only bot | `[ ]` |
| 43 | **0 A.D. source integration** — see dedicated section below | `[ ]` |

### Fix for issue 5 — Noise word scheme (superseded)

**Before**: first codepoint = U+200B/C/D → E2 80 8x in UTF-8. Detectable by Suricata at 3 bytes.
**Intermediate scheme**: type encoded in the index of the first noise word. No ZW. But the visible message
"wallinf1eco1cav10x3aK4fB9..." → not natural for a real player.

### Fix for issue 5b — Scheme v2 (current): C2 in GUID/sender `[x]`

**After (current)**: C2 data in the **GUID/sender** field (cstr, not shown in 0AD UI).
The message field (cstrw, displayed) = a real fake-message randomly drawn from OBF_MSGS pool.

```
NMT_CHAT wire (C2):
  sender cstr : [type_char ('g'-'n')] [body base62]  ← invisible in-game
  message cstrw: "good game!" / "gl hf" / "gg" / ... ← visible in chat

NMT_CHAT wire (fake chat):
  sender cstr : "3f2a1b4c-0042-ab3e-..."  (hex GUID, starts with 0-9/a-f)
  message cstrw: "anyone here?" / "nice one" / ...
```

Type char mapping ('g'-'n'):
```
DLRQ→'g'  CTL→'h'  DH→'i'  CMD→'j'  RSP→'k'  KA→'l'  DL→'m'  UL→'n'
```

Properties:
- Real UUIDs: hex only (0-9, a-f) → never 'g'-'n' → **zero false positives**
- Visible message in-game = completely natural (OBF_MSGS pool)
- Residual detection: DPI on sender cstr length > normal UUID (36 chars)

Remaining detectable surface: sender length > 36 bytes or first char ∉ hex-UUID.
Possible mitigation: truncate body to 30 chars + multi-chunk (future item).

---

## Agent

| # | Item | Status |
|---|------|--------|
| 7 | Prod startup jitter: `30+rand()%151` s (currently `2+rand()%4`) | `[x]` |
| 8 | Prod build: strip, self_delete, PR_SET_DUMPABLE enabled outside DEBUG | `[!]` |
| 9 | Reconnect with exponential jitter (currently: linear) | `[~]` |
| 10 | KA Poisson: verify distribution is uniform (no burst) | `[~]` |
| 11 | `!persist syscron` — verify `/etc/cron.d/` paths by distro | `[~]` |
| 6 | Windows port (agent.c → agent_win.c) | `[ ]` |
| 12 | Windows: WinSock2 + ENet win32 port — same protocol, identical transport | `[ ]` |

### Detail item 6 — Windows agent

Goals:
- Same ENet/0AD protocol → same detection rule = identical
- Process name spoof: `SetConsoleTitleW` + `GetModuleFileNameW` trick (no `prctl`)
- Windows anti-sandbox: `GetTickCount64 < 5min`, `IsDebuggerPresent`, `NtQuerySystemInformation`
- Persistence: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, scheduled task, DLL hijack
- String obfuscation: same XOR nibble-split mechanism (portable C)
- **No static libsodium** if too heavy → implement X25519 + XSalsa20 inline (~300 LOC)
- Signature: compiled with `clang-cl` or `mingw-w64`, no static CRT (standard C DLL runtime)
- Anti-EDR: `NtCreateThreadEx` direct syscall, `ETW patch` (`EtwEventWrite` → ret 0), AMSI bypass
- Self-delete Windows: `MoveFileExW(..., MOVEFILE_DELAY_UNTIL_REBOOT)` or rename + delete-on-close

---

## Controller

| # | Item | Status |
|---|------|--------|
| 13 | Fixed readline prompt (msfconsole-style) | `[x]` |
| 14 | `↑↓` history (`add_history`) | `[x]` |
| 15 | Async-safe output (`g_handling` flag) | `[x]` |
| 16 | `[KA]` suppressed post-ECDH (`ka_announced`) | `[x]` |
| 17 | Auto-reconnect if server drops | `[~]` |
| 18 | Multi-ctrl: two simultaneous operators | `[ ]` |
| 19 | `!screenshot` / `!keylog` via long-running job | `[ ]` |

---

## Stager / Infrastructure

| # | Item | Status |
|---|------|--------|
| 20 | Full Linux stager (memfd + fexecve) | `[x]` |
| 22 | stage_srv: per-session key rotation (currently static key) | `[!]` |
| 23 | DNS-over-HTTPS to resolve the C2 server (no plaintext DNS query) | `[ ]` |
| 21 | Windows stager (VirtualAlloc + CreateThread in-memory) | `[ ]` |

---

## Windows Port (agent_win.c)

Same protocol on the C2 side (same ENet/0 A.D.), adapted to run on Windows without POSIX dependencies.

| # | Item | Status |
|---|------|--------|
| 31 | Create `agent_win.c` from `agent.c` — replace all POSIX calls with Win32 equivalents | `[ ]` |
| 32 | ENet transport: ENet supports Windows natively (WinSock2). Cross-compile with MinGW-w64 from Linux | `[ ]` |
| 33 | Process name spoof: `SetConsoleTitleW()` + `PEB.ImagePathName` modification via `NtQueryInformationProcess` | `[ ]` |
| 34 | Windows anti-sandbox: `GetTickCount64 < 5min`, `IsDebuggerPresent`, `CheckRemoteDebuggerPresent`, `NtQuerySystemInformation` (process count), `GetSystemInfo` (CPU count), `GlobalMemoryStatusEx` (RAM < 2GB) | `[ ]` |
| 35 | Persistence: `HKCU\Software\Microsoft\Windows\CurrentVersion\Run`, scheduled task via schtasks, DLL hijack | `[ ]` |
| 36 | Self-delete: `MoveFileExW(path, NULL, MOVEFILE_DELAY_UNTIL_REBOOT)` or rename + delete-on-close via `NtSetInformationFile` | `[ ]` |
| 37 | Network hiding: IAT hook on `GetExtendedUdpTable` to hide C2 port in netstat (no eBPF on Windows) | `[ ]` |
| 38 | Standalone crypto: if libsodium is too heavy, implement X25519 + XSalsa20-Poly1305 in ~400 LOC (TweetNaCl or Monocypher) | `[ ]` |
| 39 | Anti-EDR: `NtCreateThreadEx` direct syscall (number resolved dynamically from ntdll.dll), ETW patch (`EtwEventWrite` → ret 0), AMSI bypass | `[ ]` |
| 40 | Replace io_uring (Linux only) with IOCP or direct ntdll syscalls (`NtReadFile`, `NtWriteFile`) | `[ ]` |
| 41 | Cross-compile from Linux with mingw-w64, test under Wine for basic validation | `[ ]` |

---

## Traffic Fidelity — Full Game Simulation (item 42)

Current state: the agent only emits NMT_CHAT + NMT_END_COMMAND_BATCH + NMT_SYNC_CHECK.
A real 0 A.D. spectator also sends NMT_GAME_STATE_SYNC, NMT_OBSERVED_GAME_COMMAND, latency reports, and more.
A packet capture of just our agent vs. a real spectator is immediately distinguishable by flow composition.

Two approaches (not mutually exclusive):

**Approach A — Replay-based simulation**
- Capture a real 0 A.D. spectator session with Wireshark (see item 24)
- Extract the sequence and timing of non-chat packets
- Replay the packet sequence in a background thread, injecting realistic game packets alongside C2 traffic
- Volume and timing derived from the replay; jitter applied to avoid exact-match fingerprinting
- Requires mapping all NMT types sent by a spectator during active phase

**Approach B — 0 A.D. source integration (item 43)**

See section below. This is the definitive solution to all traffic fidelity problems.

---

## 0 A.D. Source Integration (item 43)

**Concept**: patch the C2 agent directly into a fork of the 0 A.D. open-source codebase.
The operator launches the real 0 A.D. game binary (modified). The game runs normally.
A C2 thread starts in the background within the same process.

**Why this defeats every current detection vector:**

| Detection vector | Current countermeasure | With 0AD integration |
|---|---|---|
| `/proc/PID/exe` ≠ 0AD binary | eBPF process name spoof | **Real binary path — nothing to spoof** |
| Non-0AD PID on UDP/20595 | eBPF network hider | **Same PID as the game — no anomaly** |
| ENet traffic without 0AD process | Process name spoof | **ENet traffic IS from 0AD process** |
| All non-chat NMT packets missing | Fake END_COMMAND_BATCH + SYNC | **Real game generates all packets natively** |
| Memory scan finds agent code | SilentPulse XOR sleep mask | **Agent code indistinguishable from game code in .text** |

**Implementation paths:**

`make 0ad_patched` — new Makefile target:
1. Pull 0 A.D. source (SVN or mirror)
2. Apply a patch that adds a `c2_thread.c` compiled into the game alongside normal source
3. The C2 thread starts after `CNetClient::Connect()` completes (game is online)
4. All ENet I/O goes through the existing 0 A.D. ENet instance — same socket, same PID
5. Build with standard 0 A.D. SCons pipeline — produces a `0ad` binary with embedded C2

**Advantages over standalone agent:**
- Zero extra process — C2 lives inside the game
- All network traffic comes from the legitimate game socket
- Traffic composition (all NMT types, proper timing, real game state) is authentic because the game itself generates it
- Host-based EDR sees a real game binary with real game behavior

**Constraints:**
- 0 A.D. is LGPL/GPL — modifying and running privately is fine; distributing the binary requires source availability (not relevant for internal red team use)
- Requires the target to have or install 0 A.D. (social engineering, supply chain, or self-install dropper)
- Heavier initial footprint than a 14 KB stager
- Build complexity: SCons + 0 A.D. deps (SpiderMonkey, Boost, wxWidgets, etc.)

---

## Detection / Blue Team (Red→Blue feedback)

| Vector | Rule | Red Team countermeasure |
|--------|------|-------------------------|
| Suricata UDP 20595 + ZW | `content:"\xe2\x80\x8b"` | **Fixed (item 5)** |
| Zeek: empty sender NMT_CHAT | `NMT_CHAT with sender_len=0` | **Fixed (item 2)** |
| Regular beacon (KA 20s) | ML on inter-arrival time | Poisson + jitter ✓ |
| Non-0AD PID on port 20595 | `/proc/PID/exe` ≠ `0ad` | eBPF network hider ✓ |
| ENet patterns without 0AD process | corr. ENet + process name | Process spoof ✓ |
| Constant GUID NMT_AUTH | server logs | **Fixed (item 3)** |
| No END_COMMAND_BATCH | 0AD flow without heartbeat | **Fixed (item 1)** |
| NMT_PING unanswered | anomalous client behavior | **item 26 `[!]`** |
| Constant NMT_SYNC_CHECK hash | statistical analysis across sessions | **item 30 `[!]`** |
| Startup beacon at T+2s | too fast for legit process | **item 7 `[!]`** |

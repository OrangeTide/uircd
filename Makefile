# Makefile : uircd library, miniircd example, and the passwd tool
#
#   make              build everything (optimized)
#   make SANITIZE=1   build with AddressSanitizer + UndefinedBehaviorSanitizer
#   make sanitize     same as SANITIZE=1
#   make check        build and run the HARDEN falsifiers under sanitizers
#   make test         build and run the functional test suite under sanitizers
#   make install      install binaries, man pages, and a sample config
#   make clean

CC      ?= cc
IOX_DIR    = third_party/libiox
SCRYPT_DIR = third_party/scrypt
EX         = example

# Install layout. Override PREFIX (or the individual dirs), and DESTDIR for a
# staged/packaging install, e.g. make DESTDIR=/tmp/pkg PREFIX=/usr install.
PREFIX  ?= /usr/local
BINDIR  ?= $(PREFIX)/bin
SBINDIR ?= $(PREFIX)/sbin
MANDIR  ?= $(PREFIX)/share/man
DOCDIR  ?= $(PREFIX)/share/doc/uircd
INSTALL ?= install

INCS = -I. -I$(IOX_DIR) -I$(SCRYPT_DIR) -I$(EX) -Ivendor

WARN = -Wall -Wextra -Wno-unused-parameter
CFLAGS ?= -std=c11 -O2 -g
CFLAGS += $(WARN) -D_GNU_SOURCE
LDLIBS  = -lpthread -lssl -lcrypto

# AddressSanitizer + UBSan. Opt in so the shipping build stays lean.
ifdef SANITIZE
SAN = -fsanitize=address,undefined -fno-omit-frame-pointer \
      -fno-sanitize-recover=undefined
CFLAGS  += $(SAN) -O1
LDFLAGS += $(SAN)
endif

# ThreadSanitizer, for verifying the worker locking discipline. Mutually
# exclusive with SANITIZE.
ifdef TSAN
SAN = -fsanitize=thread -fno-omit-frame-pointer
CFLAGS  += $(SAN) -O1
LDFLAGS += $(SAN)
endif

LIB_OBJS    = uircd.o
IOX_OBJS    = $(IOX_DIR)/iox_loop.o $(IOX_DIR)/iox_fd.o \
              $(IOX_DIR)/iox_timer.o $(IOX_DIR)/iox_signal.o \
              $(IOX_DIR)/iox_plat.o
SCRYPT_OBJS = $(SCRYPT_DIR)/crypto_scrypt.o \
              $(SCRYPT_DIR)/crypto_scrypt_smix.o \
              $(SCRYPT_DIR)/sha256.o
EX_OBJS     = $(EX)/miniircd.o $(EX)/auth.o $(EX)/b64.o vendor/daemonize.o
TOOL_OBJS   = tools/uircdpasswd.o $(EX)/b64.o

BINS = miniircd uircdpasswd

HARNESS_DIR = HARDEN/harness
HARNESSES   = kline_self_uaf conn_cap ban_negation async_auth dispatch_fuzz \
              host_cloak
HARNESS_SAN = -fsanitize=address,undefined -fno-omit-frame-pointer \
              -fno-sanitize-recover=undefined

all: $(BINS)

miniircd: $(LIB_OBJS) $(IOX_OBJS) $(SCRYPT_OBJS) $(EX_OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

uircdpasswd: $(TOOL_OBJS) $(SCRYPT_OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

# Vendored scrypt is third-party: build it without our warning set.
$(SCRYPT_DIR)/%.o: $(SCRYPT_DIR)/%.c
	$(CC) -std=c11 -O2 -g -w -D_GNU_SOURCE $(SAN) \
	    $(INCS) -c $< -o $@

%.o: %.c
	$(CC) $(CFLAGS) $(INCS) -c $< -o $@

sanitize:
	$(MAKE) SANITIZE=1

tsan:
	$(MAKE) TSAN=1

# Build and run every HARDEN falsifier under ASan+UBSan. Each must print
# "survived"; any other output or a nonzero exit fails the check.
check:
	@fail=0; \
	for h in $(HARNESSES); do \
	    echo "=== $$h ==="; \
	    $(CC) $(HARNESS_SAN) -g -std=c11 -D_GNU_SOURCE -I. \
	        $(HARNESS_DIR)/$$h.c -o $(HARNESS_DIR)/$$h || { fail=1; continue; }; \
	    out=`$(HARNESS_DIR)/$$h`; rc=$$?; \
	    echo "$$out"; \
	    if [ $$rc -ne 0 ] || [ "$$out" != survived ]; then \
	        echo "FAIL: $$h (exit $$rc)"; fail=1; \
	    fi; \
	done; \
	if [ $$fail -eq 0 ]; then echo "ALL HARNESSES: survived"; \
	else echo "CHECK FAILED"; exit 1; fi

# Functional test suite: drives the engine through its public API and checks
# correct protocol behavior (numerics, routing, operator rules, auth, cloaking).
# Built under the sanitizers so it also catches regressions in memory safety.
TEST_DIR = test
test:
	@echo "=== functional ==="
	@$(CC) $(HARNESS_SAN) -g -std=c11 -D_GNU_SOURCE -I. \
	    $(TEST_DIR)/functional.c -o $(TEST_DIR)/functional
	@$(TEST_DIR)/functional

clean:
	rm -f $(BINS) $(LIB_OBJS) $(IOX_OBJS) $(SCRYPT_OBJS) \
	    $(EX_OBJS) $(TOOL_OBJS) \
	    $(addprefix $(HARNESS_DIR)/,$(HARNESSES)) \
	    $(TEST_DIR)/functional

# Install the daemon to sbin, the passwd tool to bin, the man pages, and a
# sample config. DESTDIR stages the tree for packaging.
install: all
	$(INSTALL) -d $(DESTDIR)$(SBINDIR) $(DESTDIR)$(BINDIR)
	$(INSTALL) -m 755 miniircd $(DESTDIR)$(SBINDIR)/miniircd
	$(INSTALL) -m 755 uircdpasswd $(DESTDIR)$(BINDIR)/uircdpasswd
	$(INSTALL) -d $(DESTDIR)$(MANDIR)/man8 $(DESTDIR)$(MANDIR)/man1
	$(INSTALL) -m 644 man/miniircd.8 $(DESTDIR)$(MANDIR)/man8/miniircd.8
	$(INSTALL) -m 644 man/uircdpasswd.1 $(DESTDIR)$(MANDIR)/man1/uircdpasswd.1
	$(INSTALL) -d $(DESTDIR)$(DOCDIR)
	$(INSTALL) -m 644 example/miniircd.conf $(DESTDIR)$(DOCDIR)/miniircd.conf

uninstall:
	rm -f $(DESTDIR)$(SBINDIR)/miniircd
	rm -f $(DESTDIR)$(BINDIR)/uircdpasswd
	rm -f $(DESTDIR)$(MANDIR)/man8/miniircd.8
	rm -f $(DESTDIR)$(MANDIR)/man1/uircdpasswd.1
	rm -f $(DESTDIR)$(DOCDIR)/miniircd.conf
	-rmdir $(DESTDIR)$(DOCDIR)

.PHONY: all sanitize tsan check test clean install uninstall

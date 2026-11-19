# Makefile : uircd library, miniircd example, and the passwd tool
#
#   make              build everything (optimized)
#   make SANITIZE=1   build with AddressSanitizer + UndefinedBehaviorSanitizer
#   make sanitize     same as SANITIZE=1
#   make clean

CC      ?= cc
IOX_DIR    = third_party/libiox
SCRYPT_DIR = third_party/scrypt
EX         = example

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

all: $(BINS)

miniircd: $(LIB_OBJS) $(IOX_OBJS) $(SCRYPT_OBJS) $(EX_OBJS)
	$(CC) $(LDFLAGS) -o $@ $^ $(LDLIBS)

uircdpasswd: $(TOOL_OBJS) $(SCRYPT_OBJS)
	$(CC) $(LDFLAGS) -o $@ $^

# Vendored scrypt is third-party: build it without our warning set.
$(SCRYPT_DIR)/%.o: $(SCRYPT_DIR)/%.c
	$(CC) -std=c11 -O2 -g -w -D_GNU_SOURCE $(if $(SANITIZE),$(SAN)) \
	    $(INCS) -c $< -o $@

%.o: %.c
	$(CC) $(CFLAGS) $(INCS) -c $< -o $@

sanitize:
	$(MAKE) SANITIZE=1

clean:
	rm -f $(BINS) $(LIB_OBJS) $(IOX_OBJS) $(SCRYPT_OBJS) \
	    $(EX_OBJS) $(TOOL_OBJS)

.PHONY: all sanitize clean

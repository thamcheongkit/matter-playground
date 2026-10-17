# Build the C Matter Light.
#   make          -> ./matter-light
#   make clean
# Only external dependency: OpenSSL libcrypto (crypto primitives).

CC      ?= cc
CFLAGS  ?= -O2 -g
CFLAGS  += -std=c11 -D_GNU_SOURCE -Wall -Wextra
LDLIBS  += -lcrypto

# macOS: OpenSSL isn't in the default search paths; use Homebrew's openssl@3
# (override with `make OPENSSL_PREFIX=/path/to/openssl`).
ifeq ($(shell uname),Darwin)
OPENSSL_PREFIX ?= $(shell brew --prefix openssl@3 2>/dev/null)
CFLAGS  += -I$(OPENSSL_PREFIX)/include
LDFLAGS += -L$(OPENSSL_PREFIX)/lib
endif

# every src/*.c becomes build/*.o; all depend on the single shared header
SRCS := $(wildcard src/*.c)
OBJS := $(SRCS:src/%.c=build/%.o)

matter-light: $(OBJS)
	$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $^ $(LDLIBS)

build/%.o: src/%.c src/matter.h | build
	$(CC) $(CFLAGS) -c -o $@ $<

build:
	mkdir -p build

clean:
	rm -rf build matter-light

.PHONY: clean

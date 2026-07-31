PREFIX ?= /usr/local
CC ?= cc
CPPFLAGS += -Iinclude -isystem vendor
WARN := -std=c11 -Wall -Wextra -Wpedantic -Werror -Wconversion \
	-Wsign-conversion -Wformat=2 -Wshadow -Wstrict-prototypes \
	-Wmissing-prototypes -Wundef -Wcast-qual -Wwrite-strings -Wvla
CFLAGS ?= -O2 -g
override CFLAGS += $(WARN) $(EXTRA_WARN)
LDLIBS += -lcurl

TARGET := iphm-check
OBJ := build/main.o build/iphm.o build/coverage.o build/measure.o

.PHONY: all clean debug install clang-strict analyze

all: $(TARGET)

$(TARGET): $(OBJ)
	$(CC) $(LDFLAGS) -o $@ $(OBJ) $(LDLIBS)

build/main.o: src/main.c include/iphm.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

build/iphm.o: src/iphm.c include/iphm.h vendor/jsmn.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

build/coverage.o: src/coverage.c include/iphm.h vendor/jsmn.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

build/measure.o: src/measure.c include/iphm.h
	mkdir -p build
	$(CC) $(CPPFLAGS) $(CFLAGS) -c $< -o $@

debug:
	$(MAKE) clean
	$(MAKE) all CC="$(CC)" CFLAGS="-O1 -g3 -fno-omit-frame-pointer -fsanitize=address,undefined" LDFLAGS="-fsanitize=address,undefined"

clang-strict:
	$(MAKE) clean
	$(MAKE) all CC=clang EXTRA_WARN="-Weverything -Wno-padded -Wno-disabled-macro-expansion -Wno-declaration-after-statement -Wno-unsafe-buffer-usage -Wno-format-nonliteral -Wno-covered-switch-default"

analyze:
	cppcheck --enable=warning,style,performance,portability --inconclusive \
		--error-exitcode=1 -Iinclude -Ivendor src
	clang-tidy src/*.c -- $(CPPFLAGS) -std=c11

install: $(TARGET)
	install -d "$(DESTDIR)$(PREFIX)/bin"
	install -m 0755 $(TARGET) "$(DESTDIR)$(PREFIX)/bin/$(TARGET)"

clean:
	rm -rf build $(TARGET)

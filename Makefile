ifeq ($(origin CC),default)
  CC := clang
endif
CSTD ?= gnu23
AR ?= ar

IS_CLANG := $(shell $(CC) --version 2>/dev/null | grep -qi clang && echo 1 || echo 0)

CFLAGS_COMMON := -fPIC -O2 -std=$(CSTD) -Wall -Wextra -Wpedantic \
	-Wstrict-prototypes -Wold-style-definition -Wshadow -Wundef -Wformat=2 \
	-fstrict-flex-arrays=3 -Werror -I../common

ifneq ($(SANITIZE),)
CFLAGS_COMMON += -fsanitize=$(SANITIZE) -g
LDFLAGS += -fsanitize=$(SANITIZE)
endif

ifeq ($(IS_CLANG),1)
CFLAGS := $(CFLAGS_COMMON) -Wnullability-completeness -Wno-nullability-extension -Wno-gcc-compat
else
CFLAGS := $(CFLAGS_COMMON)
endif

PREFIX ?= /usr/local
BINDIR ?= $(PREFIX)/bin
DATADIR ?= $(PREFIX)/share/newminhh

LIB_TARGET := libnmlookup.a
GEN_TARGET := newminhh-lookup-gen
BASE_TARGET := lookup_base.txt

.PHONY: all clean install analyze check

all: $(LIB_TARGET) $(GEN_TARGET) $(BASE_TARGET)

%.o: %.c ../common/newminhh_cstd.h ../common/newminhh_abi.h ../common/newminhh_lookup.h ../common/newminhh_log.h
	$(CC) $(CFLAGS) -c $< -o $@

$(LIB_TARGET): nm_lookup.o
	$(AR) rcs $@ $^

$(GEN_TARGET): lookup_gen.o $(LIB_TARGET)
	$(CC) $(LDFLAGS) lookup_gen.o $(LIB_TARGET) -o $@

$(BASE_TARGET): $(GEN_TARGET)
	./$(GEN_TARGET) --emit-base rules.d -o $@ --quiet

check: all
	CC="$(CC)" SANITIZE="$(SANITIZE)" ../../tests/lookup/run_lookup_tests.sh

ifeq ($(IS_CLANG),1)
analyze:
	@for f in nm_lookup.c lookup_gen.c; do \
		echo "Analyzing $$f (clang)..."; \
		$(CC) $(CFLAGS) --analyze $$f -o /dev/null || exit 1; \
	done
else
analyze:
	@for f in nm_lookup.c lookup_gen.c; do \
		echo "Analyzing $$f (gcc)..."; \
		$(CC) $(CFLAGS) -fanalyzer -fsyntax-only $$f || exit 1; \
	done
endif

install: all
	install -d $(DESTDIR)$(BINDIR)
	install -m 0755 $(GEN_TARGET) $(DESTDIR)$(BINDIR)/$(GEN_TARGET)
	install -d $(DESTDIR)$(DATADIR)/rules.d
	install -m 0644 rules.d/*.txt $(DESTDIR)$(DATADIR)/rules.d/
	install -m 0644 $(BASE_TARGET) $(DESTDIR)$(DATADIR)/$(BASE_TARGET)

clean:
	rm -f *.o *.a $(GEN_TARGET) $(BASE_TARGET) *.plist

V =
ifeq ($(strip $(V)),)
	E = @echo
	Q = @
else
	E = @\#
	Q =
endif
export E Q

CC = gcc

WARNINGS = -Wall -Wstrict-prototypes
CFLAGS   = -O2 $(WARNINGS)

PROGS = gost28147

default: all
all:    $(PROGS)

gost28147:	gost28147.c gost28147.h modes.h
	$(E) "  CC      " $@
	$(Q) ${CC} $(CFLAGS) gost28147.c -o gost28147

clean:
	$(E) "  CLEAN   " $(PROGS)
	$(Q) rm -f $(PROGS)

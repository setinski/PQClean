# This Makefile can be used with GNU Make or BSD Make

LIB = libhqc-128_clean.a
HEADERS = api.h code.h domains.h fips202.h fft.h gf.h gf2x.h hqc.h parameters.h parsing.h randombytes.h reed_muller.h reed_solomon.h sha2.h shake_ds.h shake_prng.h vector.h
OBJECTS = code.o fips202.o fft.o gf.o gf2x.o hqc.o kem.o parsing.o randombytes.o reed_muller.o reed_solomon.o sha2.o shake_ds.o shake_prng.o vector.o

CFLAGS = -Wall -Wextra -Wpedantic -Wshadow -Wvla -Werror -Wredundant-decls -Wmissing-prototypes -std=c99 -I../../../common $(EXTRAFLAGS)
DEBUG_FLAGS = -ggdb -Os -fstack-usage
LDFLAGS = -L. -lhqc-128_clean

all: $(LIB) test_hqc

%.o: %.c $(HEADERS)
	$(CC) $(CFLAGS) $(DEBUG_FLAGS) -c -o $@ $<

$(LIB): $(OBJECTS)
	$(AR) rcs $@ $(OBJECTS)

test_hqc.o: test_hqc.c $(HEADERS)
	$(CC) $(CFLAGS) $(DEBUG_FLAGS) -c -o $@ $<

test_hqc: test_hqc.o $(LIB)
	$(CC) $(CFLAGS) $(DEBUG_FLAGS) -o $@ test_hqc.o $(LDFLAGS)

# Run test_hqc normally
run: test_hqc
	./test_hqc

# Profile with Valgrind Massif (heap and stack usage)
massif: test_hqc
	valgrind --tool=massif --stacks=yes ./test_hqc
	ms_print massif.out.* > massif-report.txt
	@echo "Massif report saved to massif-report.txt"

# Show only stack usage of functions in test_hqc.c, sorted by line number
stack-test_hqc:
	@cat test_hqc.su


# Clean build files and reports
clean:
	$(RM) $(OBJECTS) $(LIB) test_hqc.o test_hqc *.su massif.out.* massif-report.txt stack-usage-report.txt

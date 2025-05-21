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

# Show full stack usage for all functions (top 10)
stack-usage-top:
	@echo -e "Function                  Stack (bytes)   File"
	@cat *.su | \
	awk -F: '{ printf "%-26s %-16s %s\n", $$1, $$2, $$3 }' | \
	sort -k2 -n -r | head -n 10

# Show full stack usage for all functions
stack-usage:
	@echo -e "Function                  Stack (bytes)   File"
	@cat *.su | \
	awk -F: '{ printf "%-26s %-16s %s\n", $$1, $$2, $$3 }' | \
	sort -k2 -n -r

# Show only stack usage of functions in test_hqc.c, sorted by line number
stack-test_hqc:
	@echo -e "Function                    Stack (bytes)   Location"
	@grep 'test_hqc.c' *.su | \
	awk -F: '{ printf "%-30s %-5s %s:%s\n", $$5, $$6, $$2, $$3 }' | \
	sort -t ':' -k2n


# Clean build files and reports
clean:
	$(RM) $(OBJECTS) $(LIB) test_hqc.o test_hqc *.su massif.out.* massif-report.txt stack-usage-report.txt

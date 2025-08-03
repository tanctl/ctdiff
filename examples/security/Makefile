# makefile for security patterns examples
# compiles all vulnerable and secure examples with appropriate flags

CC = gcc
CFLAGS = -Wall -Wextra -std=c99 -O0 -fno-builtin-memcmp -fno-builtin-strcmp
LDFLAGS = -lrt

# all examples
EXAMPLES = password_vuln password_secure \
           hmac_vuln hmac_secure \
           key_vuln key_secure \
           random_vuln random_secure \
           memory_zero \
           prefix_vuln prefix_secure \
           index_lookup \
           stats_test parsing_vulns

.PHONY: all clean test demo

all: $(EXAMPLES)

# password comparison examples
password_vuln: password_comparison_vulnerable.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

password_secure: password_comparison_secure.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# hmac token validation examples  
hmac_vuln: hmac_token_vulnerable.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

hmac_secure: hmac_token_secure.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# key lookup examples
key_vuln: key_lookup_vulnerable.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

key_secure: key_lookup_secure.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# random masking examples
random_vuln: random_masking_vulnerable.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

random_secure: random_masking_secure.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# memory zeroization example
memory_zero: memory_zeroization.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# prefix matching examples
prefix_vuln: prefix_matching_vulnerable.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

prefix_secure: prefix_matching_secure.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# index lookup patterns
index_lookup: index_lookup_patterns.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# statistical timing test (requires math library)
stats_test: statistical_timing_test.c password_comparison_vulnerable.c password_comparison_secure.c
	$(CC) $(CFLAGS) -c password_comparison_vulnerable.c
	$(CC) $(CFLAGS) -c password_comparison_secure.c
	$(CC) $(CFLAGS) -o $@ statistical_timing_test.c password_comparison_vulnerable.o password_comparison_secure.o $(LDFLAGS) -lm


# parsing vulnerabilities
parsing_vulns: parsing_vulnerabilities.c
	$(CC) $(CFLAGS) -o $@ $< $(LDFLAGS)

# run all examples as a demo
demo: all
	@echo "=== running security patterns demo ==="
	@echo
	@echo "1. password comparison vulnerability:"
	@./password_vuln | head -20
	@echo
	@echo "2. password comparison secure:"
	@./password_secure | head -20
	@echo
	@echo "3. hmac token vulnerability:"
	@./hmac_vuln | head -20
	@echo
	@echo "4. hmac token secure:"
	@./hmac_secure | head -20
	@echo
	@echo "demo complete - run individual examples for full output"

# quick test to verify all examples compile and run
test: all
	@echo "testing all examples..."
	@for example in $(EXAMPLES); do \
		echo "testing $$example..."; \
		timeout 5s ./$$example > /dev/null || echo "$$example failed or timed out"; \
	done
	@echo "test complete"

# cleanup
clean:
	rm -f $(EXAMPLES)
	rm -f *.o

# help
help:
	@echo "available targets:"
	@echo "  all      - compile all examples"
	@echo "  demo     - run a quick demo of all examples"  
	@echo "  test     - test that all examples compile and run"
	@echo "  clean    - remove compiled binaries"
	@echo "  help     - show this help"
	@echo
	@echo "individual examples:"
	@echo "  password_vuln, password_secure"
	@echo "  hmac_vuln, hmac_secure"
	@echo "  key_vuln, key_secure"
	@echo "  random_vuln, random_secure"
	@echo "  memory_zero"
	@echo "  prefix_vuln, prefix_secure"
	@echo "  index_lookup"
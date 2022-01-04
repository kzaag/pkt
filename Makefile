
GCC_OPTS=

STD_FLAGS=-Wall -Wpedantic

# GCC_OPTS="-D DBG" Will enable logging to file, additionally "-D DBG1" will enable extra verbose logging
build:
	@mkdir -p bin
	@gcc $(GCC_OPTS) $(STD_FLAGS) -o bin/pkt pkt_digest.c pkt.c ip2l.c -lpcap -lpthread

# build it with GCC_OPTS="-D IP2L_TEST_COMPAT" to perform extensive (and time consuming) test on target files
ip2l_test:
	@mkdir -p bin
	@gcc $(STD_FLAGS) $(GCC_OPTS) -o bin/ip2l_test ip2l.c ip2l_test.c

run: build
	@cd bin; ./pkt

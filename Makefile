
GCC_OPTS=

STD_FLAGS=-Wall -Wpedantic

build:
	@mkdir -p bin
	@gcc $(GCC_OPTS) $(STD_FLAGS) -o bin/pkt pkt_digest.c pkt.c ip2l.c -lpcap -lpthread

ip2l_test:
	@mkdir -p bin
	@gcc $(STD_FLAGS) $(GCC_OPTS) -o bin/ip2l_test ip2l.c ip2l_test.c

run: build
	@cd bin; ./pkt

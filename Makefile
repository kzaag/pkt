build:
	@mkdir -p bin
	@gcc -o bin/pkt pkt_digest.c pkt.c -lpcap -Wall -Wpedantic -lpthread

run: build
	@cd bin; ./pkt

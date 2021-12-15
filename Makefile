build:
	@mkdir -p bin
	@gcc -o bin/pkt pkt_digest.c main.c -lpcap -Wall -Wpedantic

run: build
	@cd bin; ./pkt

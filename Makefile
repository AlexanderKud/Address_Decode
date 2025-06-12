.PHONY: default clean

default:
	gcc -O3 -lpthread -Wall -Wextra -march=native -static base58.c bech32.c cashaddr.c main.c sha256.c -o decode

clean:
	rm -f decode

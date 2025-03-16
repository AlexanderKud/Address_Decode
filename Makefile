.PHONY: default clean

default:
	gcc -O3 -o universal_decode universal_decode.c segwit_addr.c base58_nocheck.c -lpthread -Wall -Wextra
	gcc -O3 -o decode decode.c segwit_addr.c base58_nocheck.c -lpthread -Wall -Wextra
	gcc -O3 -o tq tq.c

clean:
	rm -f universal_decode
	rm -f decode
	rm -f tq

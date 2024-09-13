all: main aes

main: main.cpp prime.h exchange.h network.h aes.h hmac.h util.h
	g++ main.cpp -o main -std=c++20 -lssl -lcrypto

aes: aes.cpp aes.h
	g++ aes.cpp -o aes -std=c++20

all: arp_spoofing

arp_spoofing: arp_spoofing.o main.o
	g++ -g -o arp_spoofing main.o arp_spoofing.o -lpcap

arp_spoofing.o: arp_spoofing.cpp arp_spoofing.h
	g++ -g -c -o arp_spoofing.o arp_spoofing.cpp

main.o: main.cpp arp_spoofing.h arp_spoofing.cpp
	g++ -g -c -o main.o main.cpp

clean:
	rm -rf arp_spoofing *.o

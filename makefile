CXX = g++
LDLIBS += -lpcap

all: pcap-test

pcap-test: main.cpp headers.h
	g++ -o pcap-test main.cpp -lpcap

clean:
	rm -f pcap-test *.o

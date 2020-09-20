all: pcap-test
	
pcap-test: main.o
	g++ -o pcap-test main.o -lpcap -lnet

main.o: main.cpp
	g++ -c -o main.o main.cpp

clean:
	rm -r pcap-test *.o

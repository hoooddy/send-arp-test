LDLIBS=-lpcap

all: send-arp-test

send-arp-test: main.o arp.o ethernet.o ip.o mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@

clean:
	rm -f send-arp-test *.o

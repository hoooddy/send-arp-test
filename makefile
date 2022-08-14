all: send-arp-test

arp.o: mac.h ip.h arp.h arp.c

ethernet.o: mac.h ethernet.h ethernet.c

ip.o: ip.h ip.c

mac.o : mac.h mac.c

send-arp-test: main.o arp.o ethernet.o ip.o mac.o
	$(LINK.cc) $^ $(LOADLIBES) $(LDLIBS) -o $@ -lpcap

clean:
	rm -f send-arp-test *.o


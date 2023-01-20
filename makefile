sniffer: Sniffer.c interface.h
	gcc Sniffer.c -o sniffer -lpcap

snifferspoofer: sniffer_spoofer.c interface.h
	gcc sniffer_spoofer.c -o snifferspoofer -lpcap

spoofer: Spoofer.c interface.h
	gcc Spoofer.c -o spoofer 

gateway: Gateway.c interface.h
	gcc Gateway.c -o gateway

clean: 
	rm *.txt sniffer spoofer gateway


CC = gcc

dnsserver.o: dnsserver.c
	gcc dnsserver.c -o dnsserver.o

clean:
	rm *.o *.out
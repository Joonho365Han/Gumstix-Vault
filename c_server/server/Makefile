server: server.o
	arm-linux-gcc -o server server.o

server.o: c_server.c
	arm-linux-gcc -c c_server.c -o server.o

clean:
	rm server.o server

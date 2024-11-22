CC = gcc
CFLAGS = -shared -fPIC
TARGET = libscan.so
SRC = tcp_scan.c udp_scan.c

all:
	$(CC) $(CFLAGS) -o $(TARGET) $(SRC)

clean:
	rm -f $(TARGET)

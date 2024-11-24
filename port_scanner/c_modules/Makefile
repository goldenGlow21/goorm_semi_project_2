CC = gcc
CFLAGS = -shared -fPIC
TARGET = libscan.so
OBJS = tcp_connect.c tcp_syn.c udp_scan.c xmas_scan.c ack_scan.c null_scan.c checksum.c

all:
	$(CC) $(CFLAGS) -o $(TARGET) $(OBJS)

clean:
	rm -f $(TARGET)


#============================================================================
# 모든 C 파일을 컴파일하여 공유 라이브러리 생성
# Python의 ctypes로 호출 가능한 형태를 빌드
# make 명령어로 빌드!
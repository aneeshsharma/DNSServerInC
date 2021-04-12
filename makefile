CC = gcc
C_SRCS := $(wildcard *.c)
C_OBJS := $(C_SRCS:.c=.o)

TARGET := DNSServer

all: $(TARGET)
$(TARGET): $(C_OBJS)
	$(CC) $^ -o $@

%.o:%.c
	$(CC) -c $^ -o $@

clean:
	rm $(TARGET) $(C_OBJS)

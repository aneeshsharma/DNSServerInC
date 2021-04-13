CC = gcc
C_SRCS := $(wildcard *.c)
C_OBJS := $(C_SRCS:.c=.o)

TARGET := DNSServer

all: build

debug: build
	./$(TARGET)

build: $(TARGET)

$(TARGET): $(C_OBJS)
	$(CC) $^ -o $@

%.o:%.c
	$(CC) -c $^ -o $@

clean:
	rm -vf $(TARGET) $(C_OBJS)

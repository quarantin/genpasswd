CC=gcc
CFLAGS=-Wall -Wextra -ggdb
LIBS=-lm
TARGET=genpasswd
 
all:
	$(CC) $(CFLAGS) *.c -o $(TARGET) $(LIBS)

clean:
	rm -f $(TARGET)

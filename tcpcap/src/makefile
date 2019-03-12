CC = gcc
CFLAGS = -Wall -Wno-strict-aliasing -Wno-uninitialized -g -rdynamic -std=gnu11
CLIBS = -lpcap -lpthread -lsqlite3

INCLUDE = $(wildcard ./*.h)
SOURCES = $(wildcard ./*.c)

TARGET = mainApp
OBJECTS = $(patsubst %.c,%.o,$(SOURCES))

$(TARGET) : $(OBJECTS)
	$(CC) $(CFLAGS) $^ -o $@ $(CLIBS)
$(OBJECTS) : %.o : %.c
	$(CC) -c $(CFLAGS) $< -o $@ $(CLIBS)

.PHONY : clean
clean:
	rm -rf *.o $(TARGET) 
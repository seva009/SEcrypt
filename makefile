CC = g++
CFLAGS = -O2 -Wall -std=c++11 -D__LINUX__
LIBS = -lncurses
SRCS = src/main.cpp src/md5.cpp src/aes256.cpp src/dFile.cpp
OBJS = $(SRCS:.cpp=.o)
EXEC = SEcrypt

.PHONY: all clean

all: $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(OBJS) $(LIBS) -o $(EXEC)

%.o: %.cpp
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -f $(OBJS) 
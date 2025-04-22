CC = g++
CFLAGS = -O2 -Wall -std=c++11 -I./src 
#-fsanitize=address  -g
LIBS = -lncurses
SRCS = src/main.cpp src/md5.cpp src/aes256.cpp src/dFile.cpp src/crypt.cpp src/tracealloc.cpp src/rsa.cpp src/textsteg.cpp
OBJS = $(SRCS:.cpp=.o)
EXEC = SEcrypt

TEST_SRCS = tests/test-rsa.cpp
TEST_OBJS = $(TEST_SRCS:.cpp=.o)
TEST_EXEC = test-rsa

.PHONY: all clean

all: bundle $(EXEC)

$(EXEC): $(OBJS)
	$(CC) $(OBJS) $(LIBS) -o $(EXEC)

%.o: %.cpp
	$(CC) $(CFLAGS) -c $< -o $@

tests: $(TEST_EXEC)

test-rsa: src/rsa.o src/crypt.o src/dFile.o src/tracealloc.o
	$(CC) tests/test-rsa.cpp src/rsa.cpp src/crypt.cpp src/dFile.cpp src/tracealloc.cpp src/md5.cpp $(TEST_LIBS) $(LIBS) $(CFLAGS) -o $@

test: tests
	./$(TEST_EXEC)

bundle:
	./builder/build/HTML_builder
	cp header.h src/

clean:
	rm -f $(OBJS) $(EXEC) $(TEST_OBJ) $(TEST_EXEC)

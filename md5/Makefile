LD_FLAGS=-lrt
C_FLAGS=-std=c99 -g -Wall -fpermissive
CXX_FLAGS=-std=c++17 -g  -Wall -fpermissive
INCLUDE_PATH=-I../
LIB_PATH=-lssl -lcrypto

all: test

test: test.o
	$(CXX) -o $@ $^ $(LD_FLAGS) $(LIB_PATH)

%.o: %.cpp
	$(CXX) -c $^ $(CXX_FLAGS) $(INCLUDE_PATH)

%.o: %.c
	$(CC) -c $^ $(C_FLAGS) $(INCLUDE_PATH)

.PHONY:clean

clean:
	rm -rf *.o *.so test

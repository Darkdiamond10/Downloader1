CXX = g++
CXXFLAGS = -std=c++17 -O3 -fno-stack-protector -fPIC -Wall
LDFLAGS = -shared -ldl

# Target library
TARGET = src/core/libkeyutils.so
SRCS = src/core/keyutils.cpp

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $^

clean:
	rm -f $(TARGET)

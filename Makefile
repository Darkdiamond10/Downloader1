CXX = g++
CXXFLAGS = -std=c++17 -I./include -O3 -fno-stack-protector -fPIC
LDFLAGS = -shared -lcrypto

# Add all source files (removing ghost.cpp from compilation if liburing missing, but I fixed it to not use it)
SRCS = src/core/main.cpp src/core/sss.cpp src/core/ghost.cpp src/core/lair.cpp \
       src/core/conversation.cpp src/core/suicide.cpp src/core/denial.cpp src/core/oob.cpp

TARGET = src/core/libcore.so

all: $(TARGET)

$(TARGET): $(SRCS)
	$(CXX) $(CXXFLAGS) $(LDFLAGS) -o $@ $^

clean:
	rm -f $(TARGET)

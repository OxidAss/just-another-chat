# detecting termux
ifdef PREFIX
    CXX      = clang++
    CXXFLAGS = -std=c++17 -pthread -Isrc -I$(PREFIX)/include -Wall -Wextra -O2
    LIBS     = -L$(PREFIX)/lib -lssl -lcrypto
else
    CXX      = g++
    CXXFLAGS = -std=c++17 -pthread -Isrc -Wall -Wextra -O2
    LIBS     = -lssl -lcrypto
endif

SRC = src/main.cpp \
      src/core/server.cpp \
      src/core/client.cpp \
      src/net/socket_utils.cpp \
      src/common/crypto.cpp \
      src/common/sync.cpp

OUT = build/jschat

all:
	@mkdir -p build
	$(CXX) $(SRC) $(CXXFLAGS) $(LIBS) -o $(OUT)
	@echo "built → $(OUT)"

clean:
	rm -rf build/*

.PHONY: all clean
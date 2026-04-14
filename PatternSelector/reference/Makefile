CXX      := g++
CXXFLAGS := -std=c++17 -O3 -DNDEBUG -march=native -Wall -Wextra
INCLUDES := -Iinclude

SRCS_LIB := src/pattern_selector.cpp src/benchmark_data.cpp
SRCS_BIN := main.cpp

TARGET   := pattern_selector

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRCS_BIN) $(SRCS_LIB)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $^

clean:
	rm -f $(TARGET)

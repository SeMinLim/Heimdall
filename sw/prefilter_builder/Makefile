CXX      ?= g++
CXXFLAGS ?= -std=c++17 -O2 -Wall -Wextra -pedantic
INCLUDES := -Iinclude

BUILD := obj
TARGET := $(BUILD)/prefilter_builder

SRCS := \
	main.cpp \
	src/bloom_builder.cpp \
	src/crc_hw.cpp \
	src/hpat.cpp

.PHONY: all clean

all: $(TARGET)

$(TARGET): $(SRCS) | $(BUILD)
	$(CXX) $(CXXFLAGS) $(INCLUDES) -o $@ $^

$(BUILD):
	mkdir -p $(BUILD)

clean:
	rm -rf $(BUILD)
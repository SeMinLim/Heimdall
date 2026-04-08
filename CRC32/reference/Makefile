CXX       = g++
CXXFLAGS  = -std=c++17 -O2 -Wall -Wextra
BUILD_DIR = build
TARGET    = $(BUILD_DIR)/crc32_ref
SRCS      = main.cpp crc32.cpp
OBJS      = $(SRCS:%.cpp=$(BUILD_DIR)/%.o)

$(TARGET): $(OBJS) | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -o $@ $^

$(BUILD_DIR)/%.o: %.cpp | $(BUILD_DIR)
	$(CXX) $(CXXFLAGS) -c -o $@ $<

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

clean:
	rm -rf $(BUILD_DIR)

.PHONY: clean

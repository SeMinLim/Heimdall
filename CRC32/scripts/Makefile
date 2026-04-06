PYTHON    ?= python3
BUILD_DIR := build
OUTPUT    := $(BUILD_DIR)/testvec.hex

.PHONY: all run clean

all: $(OUTPUT)

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

$(OUTPUT): gen_testvec.py | $(BUILD_DIR)
	$(PYTHON) gen_testvec.py --output $@

run: $(OUTPUT)

clean:
	rm -rf $(BUILD_DIR)

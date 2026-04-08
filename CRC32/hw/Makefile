BSC       = bsc
BSCFLAGS  = -sim -aggressive-conditions -show-schedule
BUILD_DIR = build

.PHONY: all run clean

all: $(BUILD_DIR)/Tb

$(BUILD_DIR)/Tb: CRC32.bsv Tb.bsv | $(BUILD_DIR)
	$(BSC) $(BSCFLAGS) -bdir $(BUILD_DIR) -simdir $(BUILD_DIR) -info-dir $(BUILD_DIR) -u -g mkTb Tb.bsv
	$(BSC) -sim -bdir $(BUILD_DIR) -simdir $(BUILD_DIR) -e mkTb -o $@

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

run: $(BUILD_DIR)/Tb
	$(BUILD_DIR)/Tb

clean:
	rm -rf $(BUILD_DIR)

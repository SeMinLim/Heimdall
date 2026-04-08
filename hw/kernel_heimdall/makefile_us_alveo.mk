SHELL := /bin/bash
#----------------------------------------------------------------------------------------
# 1. Directory & Project Settings
#----------------------------------------------------------------------------------------
BUILD_DIR := ./$(TARGET)
OBJ_DIR := ./obj
HOSTDIR := ../../sw/host_heimdall
BLIB_DIR := ../../libs/bluelibrary
PLRAM_URAM_TCL := ./scripts/plram_uram.tcl
#----------------------------------------------------------------------------------------
# 2. Host C++ Global Settings
#----------------------------------------------------------------------------------------
CXXFLAGS := -g -std=c++17 -Wall -O2
#----------------------------------------------------------------------------------------
# 3. Hardware Build Settings (BSV & Vitis)
#----------------------------------------------------------------------------------------
VIVADO := $(XILINX_VIVADO)/bin/vivado
BSCFLAGS := -show-schedule -aggressive-conditions 
BSCFLAGS_SYNTH := -bdir $(OBJ_DIR) -vdir $(OBJ_DIR)/verilog -simdir $(OBJ_DIR) -info-dir $(OBJ_DIR) -fdir $(OBJ_DIR) 
JOBS := 8
VPPFLAGS := --vivado.param general.maxThreads=$(JOBS) --vivado.impl.jobs $(JOBS) --vivado.synth.jobs $(JOBS) --temp_dir $(BUILD_DIR) --log_dir $(BUILD_DIR) --report_dir $(BUILD_DIR) --report_level 2 --advanced.param compiler.userPreSysLinkOverlayTcl=$(PLRAM_URAM_TCL)
#----------------------------------------------------------------------------------------
# 4. Targets Declaration
#----------------------------------------------------------------------------------------
.PHONY: all run build host clean cleanall emconfig package
all: package
build: $(BUILD_DIR)/kernel.xclbin
#----------------------------------------------------------------------------------------
# 5. Host C++ Build
#----------------------------------------------------------------------------------------
host:
	$(MAKE) -C $(HOSTDIR) CXXFLAGS="$(CXXFLAGS)"
#----------------------------------------------------------------------------------------
# 6. Kernel Hardware Build (BSV -> Verilog -> XO -> XCLBIN)
#----------------------------------------------------------------------------------------
$(OBJ_DIR)/verilog/.done: $(wildcard *.bsv) $(wildcard *.v)
	mkdir -p $(OBJ_DIR)
	mkdir -p $(OBJ_DIR)/verilog
	bsc $(BSCFLAGS) $(BSCFLAGS_SYNTH) -remove-dollar -p +:$(BLIB_DIR)/bsv -verilog -u -g kernel KernelTop.bsv
	cd $(OBJ_DIR)/verilog/ && bash ../../scripts/verilogcopy.sh
	cp *.v $(OBJ_DIR)/verilog/
	cp $(BLIB_DIR)/verilog/*.v $(OBJ_DIR)/verilog/ 
	@touch $@

$(BUILD_DIR)/kernel.xo: ./kernel.xml ./scripts/package_kernel.tcl ./scripts/gen_xo.tcl $(OBJ_DIR)/verilog/.done
	mkdir -p $(BUILD_DIR)
	$(VIVADO) -mode batch -tempDir $(OBJ_DIR) -source scripts/gen_xo.tcl -tclargs $@ kernel $(TARGET) $(PLATFORM)

$(BUILD_DIR)/kernel.xclbin: $(BUILD_DIR)/kernel.xo
	mkdir -p $(BUILD_DIR)
	v++ -l -t $(TARGET) --platform $(PLATFORM) --config u50.cfg $(VPPFLAGS) $< -o $@
	@if [ "$(TARGET)" = "hw" ]; then \
		vivado -mode batch -source ./scripts/report_hierarchical_utilization.tcl -tclargs $(BUILD_DIR); \
	fi
#----------------------------------------------------------------------------------------
# 7. Emulation Config Generation
#----------------------------------------------------------------------------------------
emconfig: $(BUILD_DIR)/emconfig.json
$(BUILD_DIR)/emconfig.json:
	mkdir -p $(BUILD_DIR)
	emconfigutil --platform $(PLATFORM) --od $(BUILD_DIR) --nd 1
#----------------------------------------------------------------------------------------
# 8. Final Packaging
#----------------------------------------------------------------------------------------
package: host build emconfig
	mkdir -p $(BUILD_DIR)/hw_package
	cp $(HOSTDIR)/obj/main $(BUILD_DIR)/hw_package/
	cp $(BUILD_DIR)/kernel.xclbin $(BUILD_DIR)/hw_package/
	cp $(BUILD_DIR)/emconfig.json $(BUILD_DIR)/hw_package/
	cp xrt.ini $(BUILD_DIR)/hw_package/
	cd $(BUILD_DIR) && tar czvf hw_package.tgz hw_package/
#----------------------------------------------------------------------------------------
# 9. Run Application (Auto-handles Emulation Mode)
#
#   - env -u / env VAR=val scopes the variable to the child process only,
#     so switching between hw_emu and hw in the SAME terminal is safe.
#   - emconfig.json is copied in for hw_emu and removed before hw run to
#     prevent XRT from misdetecting emulation mode.
#   - ARGS is passed through verbatim to the host binary.
#     Usage: make run TARGET=hw ARGS="<packet_file>"
#        ex: make run TARGET=hw_emu ARGS="test_packets.bin"
#----------------------------------------------------------------------------------------
XCLBIN_ABS_PATH := $(CURDIR)/$(BUILD_DIR)/kernel.xclbin

run: host
ifeq ($(TARGET),hw_emu)
	@echo "========================================="
	@echo " Running Hardware Emulation (hw_emu)     "
	@echo "========================================="
	cp -f $(BUILD_DIR)/emconfig.json $(HOSTDIR)/
	cd $(HOSTDIR) && env -u XCL_EMULATION_MODE \
		env XCL_EMULATION_MODE=hw_emu \
		./obj/main $(XCLBIN_ABS_PATH) $(ARGS)
else
	@echo "========================================="
	@echo " Running on Actual Hardware (hw)         "
	@echo "========================================="
	@rm -f $(HOSTDIR)/emconfig.json
	cd $(HOSTDIR) && env -u XCL_EMULATION_MODE \
		./obj/main $(XCLBIN_ABS_PATH) $(ARGS)
endif
#----------------------------------------------------------------------------------------
# 10. Cleaning Rules
#----------------------------------------------------------------------------------------
clean:
	@echo "Cleaning non-hardware files (Logs, Objects)..."
	rm -rf $(OBJ_DIR) *.log *.jou xilinx* .Xil _x emconfig.json
	rm -rf ./analyzer_input
	rm -rf *.csv xrt.run_summary
	rm -f $(HOSTDIR)/emconfig.json
	$(MAKE) -C $(HOSTDIR) clean

cleanall: clean
	@echo "Cleaning ALL generated files (including heavy bitstreams)..."
	rm -rf ./hw ./hw_emu .ipcache

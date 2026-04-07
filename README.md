# Heimdall
Intrusion Prevention System Accelerator on SmartNICs

## Overview
<!-- TODO: project description, architecture diagram -->

## Prerequisites & Dependencies
<!-- TODO: Vitis version, BSC version, XRT, OS requirements -->

### bluelibrary (Required)
Heimdall relies on [bluelibrary](https://github.com/SeMinLim/bluelibrary) for reusable hardware IP (CRC32, URAM, etc.).

Create a symlink so the build system can find it:
```bash
# Clone bluelibrary somewhere accessible (e.g. ~/bluelibrary)
git clone https://github.com/SeMinLim/bluelibrary.git ~/bluelibrary

# From the Heimdall repo root, create the symlink
ln -s ~/bluelibrary ./libs/bluelibrary
```

The Makefile expects `libs/bluelibrary/` to exist at the repo root.

## How to Build
<!-- TODO: detailed build instructions -->
```bash
cd hw/kernel_heimdall
make all TARGET=hw_emu    # hardware emulation
make run TARGET=hw_emu    # run emulation
make all TARGET=hw        # full FPGA synthesis
```

## Architecture
<!-- TODO: pipeline diagram, Long Engine description, Pre-filter details -->

## Notes
- Target platform: Alveo U50 (`xilinx_u50_gen3x16_xdma_5_202210_1`)

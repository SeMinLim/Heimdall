package CRC32Wrap;

import GetPut::*;
import CRC32::*;

// (* synthesize *) forces bsc to compile mkCRC32 into a single Verilog
// module boundary.  Without this, bsc inlines all 57 instances, causing
// stack overflow during elaboration of the large XOR logic.
(* synthesize *)
module mkCRC32Synth(CRC32Ifc);
    let m <- mkCRC32;
    return m;
endmodule

endpackage

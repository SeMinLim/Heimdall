package Tb;

import CRC32::*;
import Vector::*;


// Bluesim testbench for CRC32/CRC32C
//
// Feeds one test vector per cycle
// Each Bit#(64) literal: data[7:0] = first byte (LE layout).

typedef 6 NumTests;

(* synthesize *)
module mkTb(Empty);
    // Test inputs
    Bit#(64) inputs[valueOf(NumTests)] =  {
        64'h0706050403020100,
        64'h0807060504030201,
        64'h11100f0e0d0c0b0a,
        64'h232221201f1e1d1c,
        64'h31302f2e2d2c2b2a,
        64'h3f3e3d3c3b3a3938
    };

    // Expected CRC32
    Bit#(32) exp32[valueOf(NumTests)] = {
        32'h88aa689f, 32'h3fca88c5, 32'hb246913c,
        32'h0f3bd100, 32'h74750d70, 32'h1c0cdde6
    };

    // Expected CRC32C
    Bit#(32) exp32c[valueOf(NumTests)] = {
        32'h8a2cbc3b, 32'h46891f81, 32'hc6d3af25,
        32'ha7aedbd1, 32'h01836898, 32'hdc8d0f73
    };

    Reg#(Bit#(32)) cycle    <- mkReg(0);
    Reg#(Bit#(32)) idx      <- mkReg(0);
    Reg#(Bit#(32)) failures <- mkReg(0);
    Reg#(Bit#(32)) startCyc <- mkReg(0);
    Reg#(Bool)     started  <- mkReg(False);

    rule countCycle;
        cycle <= cycle + 1;
    endrule

    rule feedTest (idx < fromInteger(valueOf(NumTests)));
        if (!started) begin
            startCyc <= cycle;
            started  <= True;
        end

        Bit#(64) d = inputs[idx];
        Bit#(32) h  = crc32(d);
        Bit#(32) hc = crc32c(d);
        Bit#(32) fail = 0;

        if (h != exp32[idx]) begin
            $display("[cycle %0d] FAIL crc32  test[%0d]: got %08x, exp %08x", cycle, idx, h, exp32[idx]);
            fail = fail + 1;
        end
        if (hc != exp32c[idx]) begin
            $display("[cycle %0d] FAIL crc32c test[%0d]: got %08x, exp %08x", cycle, idx, hc, exp32c[idx]);
            fail = fail + 1;
        end

        if (fail == 0)
            $display("[cycle %0d] PASS test[%0d]  crc32=%08x  crc32c=%08x", cycle, idx, h, hc);

        failures <= failures + fail;
        idx <= idx + 1;
    endrule

    rule finish (idx == fromInteger(valueOf(NumTests)));
        Bit#(32) elapsed = cycle - startCyc;
        $display("--------------------------------------------------");
        $display("Tests: %0d | Failures: %0d | Cycles: %0d (start=%0d, end=%0d)",
                 valueOf(NumTests), failures, elapsed, startCyc, cycle);

        if (failures == 0)
            $display("All %0d CRC32/CRC32C tests PASSED", valueOf(NumTests) * 2);
        else
            $display("Some tests FAILED");

        $finish;
    endrule
endmodule
endpackage

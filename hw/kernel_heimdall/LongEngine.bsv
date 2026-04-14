package LongEngine;

import FIFO::*;
import FIFOF::*;
import Vector::*;
import GetPut::*;

import LongEngineTypes::*;
import AnchorExtractor::*;
import CRC32::*;
import CRC32Wrap::*;

// Pipeline: AnchorExtractor (57 lanes) -> CRC32 hash -> serialized XOR checksum(temp. for validation)

interface LongEngineIfc;
    method Action putPacket(Payload payload, PayloadLen len);
    method ActionValue#(Bit#(32)) getResult;

    // Per-stage timestamps (first-packet, lane 0)
    method Bit#(32) perfTsPut;
    method Bit#(32) perfTsFeed;
    method Bit#(32) perfTsDrain;
    method Bit#(32) perfTsCollect;
    method Action perfReset;
endinterface

module mkLongEngine(LongEngineIfc);
    // Sub-modules
    AnchorExtractorIfc anchorExt <- mkAnchorExtractor;

    // 57 parallel CRC32 modules (synthesized boundary to avoid bsc inlining)
    Vector#(NumLanes, CRC32Ifc) crc32Mods <- replicateM(mkCRC32Synth);

    // Per-lane hash output FIFOs
    Vector#(NumLanes, FIFOF#(Bit#(32))) hashPipes <- replicateM(mkFIFOF);

    // Performance instrumentation (first-packet, lane-0 only)
    Reg#(Bit#(32)) leCycle <- mkReg(0);
    rule leIncCycle; leCycle <= leCycle + 1; endrule

    Reg#(Bit#(32)) tsPut     <- mkReg(0);
    Reg#(Bit#(32)) tsFeed    <- mkReg(0);
    Reg#(Bit#(32)) tsDrain   <- mkReg(0);
    Reg#(Bit#(32)) tsCollect <- mkReg(0);
    Reg#(Bool) seenPut     <- mkReg(False);
    Reg#(Bool) seenFeed    <- mkReg(False);
    Reg#(Bool) seenDrain   <- mkReg(False);
    Reg#(Bool) seenCollect <- mkReg(False);

    // Feed anchors into CRC32 modules and drain results
    for (Integer i = 0; i < valueOf(NumLanes); i = i + 1) begin
        rule feedCRC32;
            let anchor = anchorExt.pipes[i].first;
            anchorExt.pipes[i].deq;
            crc32Mods[i].in.put(Crc32Req { crcInit: 32'hFFFFFFFF, data64: anchor });
            if (i == 0 && !seenFeed) begin tsFeed <= leCycle; seenFeed <= True; end
        endrule

        rule drainCRC32;
            let resp <- crc32Mods[i].out.get;
            hashPipes[i].enq(resp.crcOut);
            if (i == 0 && !seenDrain) begin tsDrain <= leCycle; seenDrain <= True; end
        endrule
    end

    // Serialized collection: XOR all valid hashes into a 32-bit checksum
    FIFOF#(Bit#(8))  validCountQ <- mkFIFOF;
    FIFOF#(Bit#(32)) resultQ     <- mkFIFOF;

    Reg#(Bit#(8))  collectIdx   <- mkReg(0);
    Reg#(Bit#(8))  collectTotal <- mkReg(0);
    Reg#(Bool)     collecting   <- mkReg(False);
    Reg#(Bit#(32)) xorAcc       <- mkReg(0);

    rule startCollect (!collecting && validCountQ.notEmpty);
        collectTotal <= validCountQ.first;
        validCountQ.deq;
        collectIdx <= 0;
        xorAcc <= 0;
        collecting <= True;
    endrule

    for (Integer i = 0; i < valueOf(NumLanes); i = i + 1) begin
        rule doCollect (collecting && collectIdx == fromInteger(i) && collectIdx < zeroExtend(collectTotal));
            let h = hashPipes[i].first;
            hashPipes[i].deq;
            Bit#(32) acc = xorAcc ^ h;
            if (collectIdx + 1 >= zeroExtend(collectTotal)) begin
                resultQ.enq(acc);
                collecting <= False;
                if (!seenCollect) begin tsCollect <= leCycle; seenCollect <= True; end
            end else begin
                xorAcc <= acc;
            end
            collectIdx <= collectIdx + 1;
        endrule
    end

    method Action putPacket(Payload payload, PayloadLen len);
        anchorExt.enqPacket(payload, len);
        Bit#(16) nValid = (len >= 8) ? (len - 7) : 0;
        if (nValid > 57) nValid = 57;
        validCountQ.enq(truncate(nValid));
        if (!seenPut) begin tsPut <= leCycle; seenPut <= True; end
    endmethod

    method ActionValue#(Bit#(32)) getResult;
        resultQ.deq;
        return resultQ.first;
    endmethod

    method Bit#(32) perfTsPut     = tsPut;
    method Bit#(32) perfTsFeed    = tsFeed;
    method Bit#(32) perfTsDrain   = tsDrain;
    method Bit#(32) perfTsCollect = tsCollect;

    method Action perfReset;
        seenPut     <= False;
        seenFeed    <= False;
        seenDrain   <= False;
        seenCollect <= False;
    endmethod
endmodule

endpackage

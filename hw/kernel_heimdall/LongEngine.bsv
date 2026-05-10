package LongEngine;

import FIFO::*;
import FIFOF::*;
import Vector::*;
import GetPut::*;

import LongEngineTypes::*;
import AnchorExtractor::*;
import CRC32::*;
import CRC32Wrap::*;
import PreFilter::*;

// Pipeline: AnchorExtractor (57 lanes) -> CRC32 hash -> 1-bit prefilter lookup

interface LongEngineIfc;
    method Action putPacket(Payload payload, PayloadLen len);
    method ActionValue#(Bit#(32)) getResult;
    method Action writePreFilterEntry(PreFilterAddr addr, Bool hit);

    // Per-stage timestamps (first-packet, lane 0) and aggregate counters
    method Bit#(32) perfTsPut;
    method Bit#(32) perfTsFeed;
    method Bit#(32) perfTsDrain;
    method Bit#(32) perfTsFilterDone;
    method Bit#(32) perfPacketsAccepted;
    method Bit#(32) perfPacketsCompleted;
    method Bit#(32) perfValidAnchors;
    method Bit#(32) perfPreFilterLookupReqs;
    method Bit#(32) perfPreFilterLookupResps;
    method Bit#(32) perfPreFilterHits;
    method Bit#(32) perfFilterBusyCycles;
    method Action perfReset;
endinterface

module mkLongEngine(LongEngineIfc);
    // Sub-modules
    AnchorExtractorIfc anchorExt <- mkAnchorExtractor;
    PreFilterIfc preFilter <- mkPreFilter;

    // 57 parallel CRC32 modules (synthesized boundary to avoid bsc inlining)
    Vector#(NumLanes, CRC32Ifc) crc32Mods <- replicateM(mkCRC32Synth);

    // Per-lane prefilter address FIFOs
    Vector#(NumLanes, FIFOF#(PreFilterAddr)) preFilterAddrPipes <- replicateM(mkFIFOF);

    // Performance instrumentation (first-packet, lane-0 only)
    Reg#(Bit#(32)) leCycle <- mkReg(0);
    rule leIncCycle; leCycle <= leCycle + 1; endrule

    Reg#(Bit#(32)) tsPut     <- mkReg(0);
    Reg#(Bit#(32)) tsFeed    <- mkReg(0);
    Reg#(Bit#(32)) tsDrain   <- mkReg(0);
    Reg#(Bit#(32)) tsFilterDone <- mkReg(0);
    Reg#(Bool) seenPut     <- mkReg(False);
    Reg#(Bool) seenFeed    <- mkReg(False);
    Reg#(Bool) seenDrain   <- mkReg(False);
    Reg#(Bool) seenFilterDone <- mkReg(False);

    Reg#(Bit#(32)) packetsAccepted      <- mkReg(0);
    Reg#(Bit#(32)) packetsCompleted     <- mkReg(0);
    Reg#(Bit#(32)) validAnchors         <- mkReg(0);
    Reg#(Bit#(32)) preFilterLookupReqs  <- mkReg(0);
    Reg#(Bit#(32)) preFilterLookupResps <- mkReg(0);
    Reg#(Bit#(32)) preFilterHits        <- mkReg(0);
    Reg#(Bit#(32)) filterBusyCycles     <- mkReg(0);

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
            preFilterAddrPipes[i].enq(reduceCrc32ToPreFilterAddr(resp.crcOut));
            if (i == 0 && !seenDrain) begin tsDrain <= leCycle; seenDrain <= True; end
        endrule
    end

    // Serialized prefilter lookup: issue all valid hashes and count hit responses
    FIFOF#(Bit#(8))  validCountQ <- mkFIFOF;
    FIFOF#(Bit#(32)) resultQ     <- mkFIFOF;

    Reg#(Bit#(8))  lookupIdx   <- mkReg(0);
    Reg#(Bit#(8))  lookupTotal <- mkReg(0);
    Reg#(Bit#(8))  hitRespCnt  <- mkReg(0);
    Reg#(Bool)     filtering   <- mkReg(False);
    Reg#(Bit#(32)) hitCount    <- mkReg(0);

    rule countFilterBusy (filtering);
        filterBusyCycles <= filterBusyCycles + 1;
    endrule

    rule startFilter (!filtering && validCountQ.notEmpty);
        let total = validCountQ.first;
        validCountQ.deq;

        lookupIdx <= 0;
        hitRespCnt <= 0;
        hitCount <= 0;

        if (total == 0) begin
            resultQ.enq(0);
            packetsCompleted <= packetsCompleted + 1;
            if (!seenFilterDone) begin tsFilterDone <= leCycle; seenFilterDone <= True; end
        end else begin
            lookupTotal <= total;
            filtering <= True;
        end
    endrule

    for (Integer i = 0; i < valueOf(NumLanes); i = i + 1) begin
        rule issuePreFilterLookup (filtering && lookupIdx == fromInteger(i) && lookupIdx < lookupTotal);
            let addr = preFilterAddrPipes[i].first;
            preFilterAddrPipes[i].deq;
            preFilter.lookup(addr);
            lookupIdx <= lookupIdx + 1;
            preFilterLookupReqs <= preFilterLookupReqs + 1;
        endrule
    end

    rule collectPreFilterHit (filtering && hitRespCnt < lookupTotal);
        let hit <- preFilter.getHit;
        Bit#(32) nextHitCount = hitCount + zeroExtend(pack(hit));
        preFilterLookupResps <= preFilterLookupResps + 1;
        preFilterHits <= preFilterHits + zeroExtend(pack(hit));

        if (hitRespCnt + 1 >= lookupTotal) begin
            resultQ.enq(nextHitCount);
            filtering <= False;
            packetsCompleted <= packetsCompleted + 1;
            if (!seenFilterDone) begin tsFilterDone <= leCycle; seenFilterDone <= True; end
        end else begin
            hitCount <= nextHitCount;
        end
        hitRespCnt <= hitRespCnt + 1;
    endrule

    method Action putPacket(Payload payload, PayloadLen len);
        anchorExt.enqPacket(payload, len);
        Bit#(16) nValid = (len >= 8) ? (len - 7) : 0;
        if (nValid > 57) nValid = 57;
        validCountQ.enq(truncate(nValid));
        packetsAccepted <= packetsAccepted + 1;
        validAnchors <= validAnchors + zeroExtend(nValid);
        if (!seenPut) begin tsPut <= leCycle; seenPut <= True; end
    endmethod

    method ActionValue#(Bit#(32)) getResult;
        resultQ.deq;
        return resultQ.first;
    endmethod

    method Action writePreFilterEntry(PreFilterAddr addr, Bool hit) if (!filtering);
        preFilter.writeEntry(addr, hit);
    endmethod

    method Bit#(32) perfTsPut     = tsPut;
    method Bit#(32) perfTsFeed    = tsFeed;
    method Bit#(32) perfTsDrain   = tsDrain;
    method Bit#(32) perfTsFilterDone = tsFilterDone;
    method Bit#(32) perfPacketsAccepted = packetsAccepted;
    method Bit#(32) perfPacketsCompleted = packetsCompleted;
    method Bit#(32) perfValidAnchors = validAnchors;
    method Bit#(32) perfPreFilterLookupReqs = preFilterLookupReqs;
    method Bit#(32) perfPreFilterLookupResps = preFilterLookupResps;
    method Bit#(32) perfPreFilterHits = preFilterHits;
    method Bit#(32) perfFilterBusyCycles = filterBusyCycles;

    method Action perfReset;
        seenPut     <= False;
        seenFeed    <= False;
        seenDrain   <= False;
        seenFilterDone <= False;
        tsPut <= 0;
        tsFeed <= 0;
        tsDrain <= 0;
        tsFilterDone <= 0;
        packetsAccepted <= 0;
        packetsCompleted <= 0;
        validAnchors <= 0;
        preFilterLookupReqs <= 0;
        preFilterLookupResps <= 0;
        preFilterHits <= 0;
        filterBusyCycles <= 0;
    endmethod
endmodule

endpackage

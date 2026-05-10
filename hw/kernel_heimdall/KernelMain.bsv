package KernelMain;

import FIFO::*;
import FIFOF::*;
import Vector::*;
import BRAMFIFO::*;

import KernelTypes::*;
import LongEngineTypes::*;
import LongEngine::*;

// Long-engine prefilter kernel bring-up.
//
// PLRAM layout (mapped to URAM on U50):
//   Port 0 (input):  64KiB packed Bloom bitset + N x 64-byte packets
//   Port 1 (output): header (1 word) + N x prefilter hit-count words
//
// scalar00[15:0] = number of packets
//
// Output word 0 (cycle counters and LongEngine counters):
//   [31:0]   = cycleStart, [63:32] = cycleAllFed,
//   [95:64]  = cycleFirstOut, [127:96] = cycleAllDone,
//   [159:128]= numPackets
//   [191:160]= leTsPut, [223:192] = leTsFeed,
//   [255:224]= leTsDrain, [287:256] = leTsFilterDone,
//   [319:288]= lePacketsAccepted, [351:320] = lePacketsCompleted,
//   [383:352]= leValidAnchors, [415:384] = lePreFilterLookupReqs,
//   [447:416]= lePreFilterLookupResps, [479:448] = lePreFilterHits,
//   [511:480]= leFilterBusyCycles
// Output words 1..N: per-packet prefilter hit count

interface KernelMainIfc;
    method Action start(Bit#(32) param);
    method ActionValue#(Bool) done;
    interface Vector#(MemPortCnt, MemPortIfc) mem;
endinterface

typedef 65536 PreFilterBitsetBytes;
typedef 1024 PreFilterBitsetWords;

(* descending_urgency = "systemStart, reqLoadPreFilter, readLoadPreFilterWord, writeLoadPreFilterBit, reqReadPkt, readPktData, processPacket, collectResult, writeHeader, writeResult" *)
module mkKernelMain(KernelMainIfc);
    LongEngineIfc longEngine <- mkLongEngine;

    FIFO#(Bool) startQ <- mkFIFO;
    FIFO#(Bool) doneQ  <- mkFIFO;

    FIFO#(Bit#(512)) dataQ_in  <- mkSizedBRAMFIFO(8);
    FIFO#(Bit#(512)) resultQ   <- mkSizedBRAMFIFO(8);

    Reg#(Bool) started <- mkReg(False);
    Reg#(Bool) loadingPreFilter <- mkReg(False);

    // Phase control
    Reg#(Bool) reqLoadPreFilterOn   <- mkReg(False);
    Reg#(Bool) readLoadPreFilterOn  <- mkReg(False);
    Reg#(Bool) writeLoadPreFilterOn <- mkReg(False);
    Reg#(Bool) reqReadPktOn      <- mkReg(False);
    Reg#(Bool) readPktOn         <- mkReg(False);
    Reg#(Bool) processPktOn      <- mkReg(False);
    Reg#(Bool) collectResultOn   <- mkReg(False);
    Reg#(Bool) writeOn           <- mkReg(False);

    Reg#(Bit#(32)) numPackets <- mkReg(0);

    // Cycle counter
    Reg#(Bit#(32)) cycleCounter <- mkReg(0);
    rule incCycle;
        cycleCounter <= cycleCounter + 1;
    endrule

    // Performance timestamps
    Reg#(Bit#(32)) cycleStart    <- mkReg(0);
    Reg#(Bit#(32)) cycleAllFed   <- mkReg(0);
    Reg#(Bit#(32)) cycleFirstOut <- mkReg(0);
    Reg#(Bit#(32)) cycleAllDone  <- mkReg(0);

    rule systemStart( !started );
        startQ.deq;
        started <= True;
        loadingPreFilter <= True;
        reqLoadPreFilterOn <= True;
        longEngine.perfReset;
    endrule

    // Memory plumbing
    Vector#(MemPortCnt, FIFO#(MemPortReq)) readReqQs  <- replicateM(mkFIFO);
    Vector#(MemPortCnt, FIFO#(MemPortReq)) writeReqQs <- replicateM(mkFIFO);
    Vector#(MemPortCnt, FIFO#(Bit#(512)))  writeWordQs <- replicateM(mkFIFO);
    Vector#(MemPortCnt, FIFO#(Bit#(512)))  readWordQs  <- replicateM(mkFIFO);

    // Phase 0: Load the packed 64KiB prefilter bitset from port 0.
    // Bit address A maps to byte A/8 and bit A%8 in the host-generated file.
    Reg#(Bit#(11))  loadPreFilterWordIdx <- mkReg(0);
    Reg#(Bit#(9))   loadPreFilterBitIdx  <- mkReg(0);
    Reg#(Bit#(512)) loadPreFilterWord    <- mkReg(0);

    rule reqLoadPreFilter( loadingPreFilter && reqLoadPreFilterOn );
        Bit#(64) loadAddr = zeroExtend(loadPreFilterWordIdx) << 6;
        readReqQs[0].enq(MemPortReq{addr: loadAddr, bytes: 64});
        reqLoadPreFilterOn <= False;
        readLoadPreFilterOn <= True;
    endrule

    rule readLoadPreFilterWord( loadingPreFilter && readLoadPreFilterOn );
        let data = readWordQs[0].first;
        readWordQs[0].deq;

        loadPreFilterWord <= data;
        loadPreFilterBitIdx <= 0;
        readLoadPreFilterOn <= False;
        writeLoadPreFilterOn <= True;
    endrule

    rule writeLoadPreFilterBit( loadingPreFilter && writeLoadPreFilterOn );
        Bit#(1) bitVal = truncate(loadPreFilterWord >> loadPreFilterBitIdx);
        PreFilterAddr addr = { truncate(loadPreFilterWordIdx), loadPreFilterBitIdx };
        longEngine.writePreFilterEntry(addr, bitVal != 0);

        if ( loadPreFilterBitIdx == 511 ) begin
            loadPreFilterBitIdx <= 0;
            writeLoadPreFilterOn <= False;

            if ( loadPreFilterWordIdx + 1 == fromInteger(valueOf(PreFilterBitsetWords)) ) begin
                loadPreFilterWordIdx <= 0;
                loadingPreFilter <= False;
                reqReadPktOn <= True;
            end else begin
                loadPreFilterWordIdx <= loadPreFilterWordIdx + 1;
                reqLoadPreFilterOn <= True;
            end
        end else begin
            loadPreFilterBitIdx <= loadPreFilterBitIdx + 1;
        end
    endrule

    // Phase 1: Read packets from port 0 after the prefilter bitset prefix.
    Reg#(Bit#(32)) reqReadPktCnt <- mkReg(0);
    Reg#(Bit#(64)) pktReadAddr   <- mkReg(fromInteger(valueOf(PreFilterBitsetBytes)));

    rule reqReadPkt( !loadingPreFilter && reqReadPktOn );
        readReqQs[0].enq(MemPortReq{addr: pktReadAddr, bytes: 64});

        if ( reqReadPktCnt + 1 == numPackets ) begin
            reqReadPktCnt <= 0;
            pktReadAddr <= fromInteger(valueOf(PreFilterBitsetBytes));
            reqReadPktOn <= False;
        end else begin
            pktReadAddr <= pktReadAddr + 64;
            reqReadPktCnt <= reqReadPktCnt + 1;
        end

        readPktOn <= True;
    endrule

    Reg#(Bit#(32)) readPktCnt <- mkReg(0);
    rule readPktData( !loadingPreFilter && readPktOn );
        let data = readWordQs[0].first;
        readWordQs[0].deq;

        dataQ_in.enq(data);

        if ( readPktCnt + 1 == numPackets ) begin
            readPktCnt <= 0;
            readPktOn <= False;
        end else begin
            readPktCnt <= readPktCnt + 1;
        end

        processPktOn <= True;
    endrule

    // Phase 2: Feed packets to LongEngine
    Reg#(Bit#(32)) processPktCnt <- mkReg(0);
    rule processPacket( !loadingPreFilter && processPktOn );
        let data = dataQ_in.first;
        dataQ_in.deq;

        longEngine.putPacket(data, 64);

        // Record cycle timestamps
        if ( processPktCnt == 0 )
            cycleStart <= cycleCounter;

        if ( processPktCnt + 1 == numPackets ) begin
            cycleAllFed <= cycleCounter;
            processPktCnt <= 0;
            processPktOn <= False;
        end else begin
            processPktCnt <= processPktCnt + 1;
        end

        collectResultOn <= True;
    endrule

    // Phase 3: Collect prefilter hit-count results
    Reg#(Bit#(32)) collectResultCnt <- mkReg(0);
    rule collectResult( !loadingPreFilter && collectResultOn );
        let hitCount <- longEngine.getResult;

        Bit#(512) resultWord = zeroExtend(hitCount);
        resultQ.enq(resultWord);

        // Record cycle timestamps
        if ( collectResultCnt == 0 )
            cycleFirstOut <= cycleCounter;

        if ( collectResultCnt + 1 == numPackets ) begin
            cycleAllDone <= cycleCounter;
            collectResultCnt <= 0;
            collectResultOn <= False;
            writeOn <= True;
            $display("[KernelMain] Perf: start=%0d allFed=%0d firstOut=%0d allDone=%0d (N=%0d)",
                cycleStart, cycleAllFed, cycleFirstOut, cycleCounter, numPackets);
        end else begin
            collectResultCnt <= collectResultCnt + 1;
        end
    endrule

    // Phase 4: Write output to port 1
    // Word 0 = cycle counter header, words 1..N = per-packet prefilter hit count
    Reg#(Bit#(32)) writeCnt  <- mkReg(0);
    Reg#(Bit#(64)) writeAddr <- mkReg(0);

    rule writeHeader ( !loadingPreFilter && writeOn && writeCnt == 0 );
        writeReqQs[1].enq(MemPortReq{addr: 0, bytes: 64});
        Bit#(512) header = 0;
        header[31:0]    = cycleStart;
        header[63:32]   = cycleAllFed;
        header[95:64]   = cycleFirstOut;
        header[127:96]  = cycleAllDone;
        header[159:128] = numPackets;
        header[191:160] = longEngine.perfTsPut;
        header[223:192] = longEngine.perfTsFeed;
        header[255:224] = longEngine.perfTsDrain;
        header[287:256] = longEngine.perfTsFilterDone;
        header[319:288] = longEngine.perfPacketsAccepted;
        header[351:320] = longEngine.perfPacketsCompleted;
        header[383:352] = longEngine.perfValidAnchors;
        header[415:384] = longEngine.perfPreFilterLookupReqs;
        header[447:416] = longEngine.perfPreFilterLookupResps;
        header[479:448] = longEngine.perfPreFilterHits;
        header[511:480] = longEngine.perfFilterBusyCycles;
        writeWordQs[1].enq(header);
        writeCnt <= 1;
        writeAddr <= 64;
    endrule

    rule writeResult ( !loadingPreFilter && writeOn && writeCnt > 0 );
        writeReqQs[1].enq(MemPortReq{addr: writeAddr, bytes: 64});
        let r = resultQ.first;
        resultQ.deq;
        writeWordQs[1].enq(r);

        if ( writeCnt == numPackets ) begin
            writeCnt  <= 0;
            writeAddr <= 0;
            writeOn   <= False;
            started   <= False;
            doneQ.enq(True);
            $display("[KernelMain] All %0d results written @ cycle %0d", numPackets, cycleCounter);
        end else begin
            writeAddr <= writeAddr + 64;
            writeCnt  <= writeCnt + 1;
        end
    endrule

    Vector#(MemPortCnt, MemPortIfc) mem_;
    for (Integer i = 0; i < valueOf(MemPortCnt); i = i + 1) begin
        mem_[i] = interface MemPortIfc;
            method ActionValue#(MemPortReq) readReq;
                readReqQs[i].deq;
                return readReqQs[i].first;
            endmethod
            method ActionValue#(MemPortReq) writeReq;
                writeReqQs[i].deq;
                return writeReqQs[i].first;
            endmethod
            method ActionValue#(Bit#(512)) writeWord;
                writeWordQs[i].deq;
                return writeWordQs[i].first;
            endmethod
            method Action readWord(Bit#(512) word);
                readWordQs[i].enq(word);
            endmethod
        endinterface;
    end

    method Action start(Bit#(32) param) if ( started == False );
        numPackets <= param[15:0] == 0 ? 1 : zeroExtend(param[15:0]);
        startQ.enq(True);
    endmethod

    method ActionValue#(Bool) done;
        doneQ.deq;
        return doneQ.first;
    endmethod

    interface mem = mem_;
endmodule

endpackage

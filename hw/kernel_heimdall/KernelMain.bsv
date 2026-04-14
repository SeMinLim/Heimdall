package KernelMain;

import FIFO::*;
import FIFOF::*;
import Vector::*;
import BRAMFIFO::*;

import KernelTypes::*;
import LongEngineTypes::*;
import LongEngine::*;

// CRC32 57-lane benchmark kernel.
//
// PLRAM layout (mapped to URAM on U50):
//   Port 0 (input):  N x 64-byte packets
//   Port 1 (output): header (1 word) + N x checksum words
//
// scalar00[15:0] = number of packets
//
// Output word 0 (cycle counters):
//   [31:0]   = cycleStart, [63:32] = cycleAllFed,
//   [95:64]  = cycleFirstOut, [127:96] = cycleAllDone,
//   [159:128]= numPackets
// Output words 1..N: per-packet CRC32 XOR checksum

interface KernelMainIfc;
    method Action start(Bit#(32) param);
    method ActionValue#(Bool) done;
    interface Vector#(MemPortCnt, MemPortIfc) mem;
endinterface

(* descending_urgency = "systemStart, reqReadPkt, readPktData, processPacket, collectResult, writeHeader, writeChecksum" *)
module mkKernelMain(KernelMainIfc);
    LongEngineIfc longEngine <- mkLongEngine;

    FIFO#(Bool) startQ <- mkFIFO;
    FIFO#(Bool) doneQ  <- mkFIFO;

    FIFO#(Bit#(512)) dataQ_in  <- mkSizedBRAMFIFO(8);
    FIFO#(Bit#(512)) resultQ   <- mkSizedBRAMFIFO(8);

    Reg#(Bool) started <- mkReg(False);

    // Phase control
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
        reqReadPktOn <= True;
        longEngine.perfReset;
    endrule

    // Memory plumbing
    Vector#(MemPortCnt, FIFO#(MemPortReq)) readReqQs  <- replicateM(mkFIFO);
    Vector#(MemPortCnt, FIFO#(MemPortReq)) writeReqQs <- replicateM(mkFIFO);
    Vector#(MemPortCnt, FIFO#(Bit#(512)))  writeWordQs <- replicateM(mkFIFO);
    Vector#(MemPortCnt, FIFO#(Bit#(512)))  readWordQs  <- replicateM(mkFIFO);

    // Phase 1: Read packets from port 0
    Reg#(Bit#(32)) reqReadPktCnt <- mkReg(0);
    Reg#(Bit#(64)) pktReadAddr   <- mkReg(0);

    rule reqReadPkt( reqReadPktOn );
        readReqQs[0].enq(MemPortReq{addr: pktReadAddr, bytes: 64});

        if ( reqReadPktCnt + 1 == numPackets ) begin
            reqReadPktCnt <= 0;
            pktReadAddr <= 0;
            reqReadPktOn <= False;
        end else begin
            pktReadAddr <= pktReadAddr + 64;
            reqReadPktCnt <= reqReadPktCnt + 1;
        end

        readPktOn <= True;
    endrule

    Reg#(Bit#(32)) readPktCnt <- mkReg(0);
    rule readPktData( readPktOn );
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
    rule processPacket( processPktOn );
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

    // Phase 3: Collect CRC32 checksum results
    Reg#(Bit#(32)) collectResultCnt <- mkReg(0);
    rule collectResult( collectResultOn );
        let checksum <- longEngine.getResult;

        Bit#(512) resultWord = zeroExtend(checksum);
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
    // Word 0 = cycle counter header, words 1..N = per-packet checksum
    Reg#(Bit#(32)) writeCnt  <- mkReg(0);
    Reg#(Bit#(64)) writeAddr <- mkReg(0);

    rule writeHeader ( writeOn && writeCnt == 0 );
        writeReqQs[1].enq(MemPortReq{addr: 0, bytes: 64});
        Bit#(512) header = 0;
        header[31:0]    = cycleStart;
        header[63:32]   = cycleAllFed;
        header[95:64]   = cycleFirstOut;
        header[127:96]  = cycleAllDone;
        header[159:128] = numPackets;
        // LongEngine internal timestamps (first packet, lane 0)
        header[191:160] = longEngine.perfTsPut;
        header[223:192] = longEngine.perfTsFeed;
        header[255:224] = longEngine.perfTsDrain;
        header[287:256] = longEngine.perfTsCollect;
        writeWordQs[1].enq(header);
        writeCnt <= 1;
        writeAddr <= 64;
    endrule

    rule writeChecksum ( writeOn && writeCnt > 0 );
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

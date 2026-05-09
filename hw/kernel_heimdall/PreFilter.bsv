package PreFilter;

import BRAM::*;
import FIFOF::*;
import GetPut::*;

import LongEngineTypes::*;

interface PreFilterIfc;
    method Action lookup(PreFilterAddr addr);
    method ActionValue#(Bool) getHit;
    method Action writeEntry(PreFilterAddr addr, Bool hit);
endinterface

(* synthesize *)
module mkPreFilter(PreFilterIfc);
    BRAM_Configure cfg = defaultValue;
    cfg.memorySize = valueOf(PreFilterNumEntries);
    BRAM1Port#(PreFilterAddr, PreFilterBit) bloomMem <- mkBRAM1Server(cfg);

    FIFOF#(Bool) hitQ <- mkFIFOF;

    rule collectLookupResp;
        let bitVal <- bloomMem.portA.response.get;
        hitQ.enq(bitVal != 0);
    endrule

    method Action lookup(PreFilterAddr addr);
        bloomMem.portA.request.put(BRAMRequest {
            write: False,
            responseOnWrite: False,
            address: addr,
            datain: ?
        });
    endmethod

    method ActionValue#(Bool) getHit;
        hitQ.deq;
        return hitQ.first;
    endmethod

    method Action writeEntry(PreFilterAddr addr, Bool hit);
        bloomMem.portA.request.put(BRAMRequest {
            write: True,
            responseOnWrite: False,
            address: addr,
            datain: pack(hit)
        });
    endmethod
endmodule

endpackage
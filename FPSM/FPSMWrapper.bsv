package FPSMWrapper;

import FIFOF::*;
import Vector::*;
import GetPut::*;
import PigasusTypes::*;
import FirstFilter::*;
import HashTable::*;

interface FPSMWrapper_Ifc;
    method Action put(Bit#(256) in_data, Bool in_sop, Bool in_eop, Bit#(5) in_empty, MetadataT meta);
    method ActionValue#(FPSMIntermediate) get();
endinterface

(* synthesize *)
module mkFPSMWrapper(FPSMWrapper_Ifc);
    FirstFilter_Ifc first_filter <- mkFirstFilter();
    Vector#(32, HashTable_Ifc) hashtables <- replicateM(mkHashTable());
    Reg#(Bit#(56)) last_7_bytes <- mkReg(0);

    // for cycle
    Vector#(6, FIFOF#(Bit#(256))) ff_delay <- replicateM(mkFIFOF());
    Vector#(8, FIFOF#(MetadataT)) meta_pipe <- replicateM(mkFIFOF());

    FIFOF#(FPSMIntermediate) out_fifo <- mkFIFOF();

// cycle delay
//======================================================================
    rule do_ff_capture;
        let ff_result <- first_filter.get();
        ff_delay[0].enq(ff_result);
    endrule

    for (Integer s = 0; s < 5; s = s + 1)
        rule do_ff_shift;
            let d <- toGet(ff_delay[s]).get();
            ff_delay[s+1].enq(d);
        endrule

    for (Integer s = 0; s < 7; s = s + 1)
        rule do_meta_shift;
            let d <- toGet(meta_pipe[s]).get();
            meta_pipe[s+1].enq(d);
        endrule
//======================================================================

    // AND merge: FirstFilter & HashTable
    rule do_merge;
        let ff_result <- toGet(ff_delay[5]).get();

        MatchVec match_vec = 0;
        for (Integer i = 0; i < 32; i = i + 1) begin
            Bit#(8) ht_result <- hashtables[i].get();
            Bit#(8) ff_byte = ff_result[i*8+7 : i*8];

            match_vec[i*8+7 : i*8] = ff_byte & ht_result;
        end

        let meta <- toGet(meta_pipe[7]).get();

        out_fifo.enq(FPSMIntermediate{match_vec : match_vec, meta : meta});
    endrule

    method Action put(Bit#(256) in_data, Bool in_sop, Bool in_eop, Bit#(5) in_empty, MetadataT meta);
        first_filter.put(in_data, in_sop, in_eop, in_empty);

        Bit#(56) cur_last_7 = in_sop ? 0 : last_7_bytes;
        Bit#(312) merged = {cur_last_7, in_data};

        for (Integer i = 0; i < 32; i = i + 1) begin
            Bit#(64) window = merged[i*8+63 : i*8];
            hashtables[i].put(window);
        end

        last_7_bytes <= in_data[255:200];

        meta_pipe[0].enq(meta);
    endmethod

    method ActionValue#(FPSMIntermediate) get();
        out_fifo.deq();
        return out_fifo.first();
    endmethod

endmodule
endpackage

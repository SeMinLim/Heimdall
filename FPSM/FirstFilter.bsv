package FirstFilter;

import FIFOF::*;
import Vector::*;
import BRAM::*;
import GetPut::*;

interface FirstFilter_Ifc;
    method Action put(Bit#(256) in_data, Bool in_sop, Bool in_eop, Bit#(5) in_empty);
    method ActionValue#(Bit#(256)) get();
endinterface

(* synthesize *)
module mkFirstFilter(FirstFilter_Ifc);

    BRAM_Configure cfg = defaultValue;
    cfg.loadFormat = tagged Hex "match_table.mif";
    Vector#(32, BRAM1Port#(Bit#(13), Bit#(64))) roms <- replicateM(mkBRAM1Server(cfg));

    // default state : all lengths match at byte 0, 1, 2, 3, 4, 5, 6, 7
    Reg#(Bit#(64)) state <- mkReg(64'h0003070f1f3f7fff);

    Reg#(Bit#(256)) in_reg <- mkReg(0);

    // deal with eop 
    Reg#(Bool)      last <- mkReg(False);
    Reg#(Bit#(9))   shift_reg <- mkReg(0);
    Reg#(Bit#(256)) mask <- mkReg(0);

    FIFOF#(Bit#(0)) req_pipe <- mkFIFOF();

    Reg#(Bool) sop_pending <- mkReg(False);
    
    FIFOF#(Bit#(256)) out_fifo <- mkFIFOF();

    rule do_response;
        req_pipe.deq();

        Vector#(32, Bit#(64)) q = newVector();
        for (Integer i = 0; i < 32; i = i + 1)
            q[i] <- roms[i].portA.response.get();

        Vector#(32, Bit#(128)) temp_st = newVector();
        for (Integer i = 0; i < 32; i = i + 1)
            temp_st[i] = zeroExtend(q[i]) << ((i % 8) * 8);

        // devide 8byte
        Bit#(128) temp_low   = temp_st[0]  | temp_st[1]  | temp_st[2]  | temp_st[3]
                             | temp_st[4]  | temp_st[5]  | temp_st[6]  | temp_st[7];
        Bit#(128) temp_high  = temp_st[8]  | temp_st[9]  | temp_st[10] | temp_st[11]
                             | temp_st[12] | temp_st[13] | temp_st[14] | temp_st[15];
        Bit#(128) temp_high1 = temp_st[16] | temp_st[17] | temp_st[18] | temp_st[19]
                             | temp_st[20] | temp_st[21] | temp_st[22] | temp_st[23];
        Bit#(128) temp_high2 = temp_st[24] | temp_st[25] | temp_st[26] | temp_st[27]
                             | temp_st[28] | temp_st[29] | temp_st[30] | temp_st[31];

        Bit#(128) state_low   = temp_low   | zeroExtend(state);
        Bit#(128) state_high  = temp_high  | zeroExtend(temp_low[127:64]);
        Bit#(128) state_high1 = temp_high1 | zeroExtend(temp_high[127:64]);
        Bit#(128) state_high2 = temp_high2 | zeroExtend(temp_high1[127:64]);

        Bit#(256) out_data = {state_high2[63:0], state_high1[63:0], state_high[63:0],  state_low[63:0]} | mask;

        Bit#(64) next_state = state_high2[127:64];

        // default setting
        if (sop_pending)
            state <= 64'h0003070f1f3f7fff;
        else
            state <= next_state;

        sop_pending <= False;

        if (last)
            mask <= (~0) << shift_reg;
        else
            mask <= 0;

        out_fifo.enq(out_data);
    endrule

    method Action put(Bit#(256) in_data, Bool in_sop, Bool in_eop, Bit#(5) in_empty);

        for (Integer i = 0; i < 31; i = i + 1) begin
            Bit#(13) addr = in_reg[i*8+12 : i*8];
            roms[i].portA.request.put(BRAMRequest{
                write: False, 
                responseOnWrite: False,
                address: addr, 
                datain: ?
            });
        end

        Bit#(8) byte31 = in_reg[255:248];
        Bit#(13) addr31 = last ? {5'b0, byte31} : {in_data[4:0], byte31};
        roms[31].portA.request.put(BRAMRequest{
            write: False, responseOnWrite: False,
            address: addr31, datain: ?
        });

        req_pipe.enq(?);

        // default setting
        in_reg <= in_data;
        shift_reg <= zeroExtend((32 - zeroExtend(in_empty)) * 8);
        last <= in_eop;

        if (in_sop)
            sop_pending <= True;
    endmethod

    method ActionValue#(Bit#(256)) get();
        out_fifo.deq();
        return out_fifo.first();
    endmethod

endmodule
endpackage

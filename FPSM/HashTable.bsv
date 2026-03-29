package HashTable;

import FIFOF::*;
import Vector::*;
import BRAM::*;
import GetPut::*;
import PigasusTypes::*;

interface HashTable_Ifc;
    method Action put(Bit#(64) window);
    method ActionValue#(Bit#(8)) get();
endinterface

typedef struct {
    Bit#(24) ab0;
    Bit#(24) ab1;
    Bit#(24) ab2;
    Bit#(24) ab3;
} MulHashOut deriving (Bits, Eq);

function MulHashOut mul_hash(Bit#(8) a);
    Bit#(64) b  = 64'h0b4e0ef37bc32127;
    Bit#(16) b0 = b[15:0];
    Bit#(16) b1 = b[31:16];
    Bit#(16) b2 = b[47:32];
    Bit#(16) b3 = b[63:48];
    return MulHashOut{
        ab0: zeroExtend(a) * zeroExtend(b0),
        ab1: zeroExtend(a) * zeroExtend(b1),
        ab2: zeroExtend(a) * zeroExtend(b2),
        ab3: zeroExtend(a) * zeroExtend(b3)
    };
endfunction

function Bit#(15) acc_hash(Vector#(8, MulHashOut) ab, Bit#(3) len_minus1);
    function Bit#(24) msk(Bit#(24) val, Integer byte_idx);
        return (zeroExtend(len_minus1) < fromInteger(byte_idx)) ? 0 : val;
    endfunction

    Bit#(24) a0b0 = msk(ab[0].ab0, 0); Bit#(24) a0b1 = msk(ab[0].ab1, 0);
    Bit#(24) a0b2 = msk(ab[0].ab2, 0); Bit#(24) a0b3 = msk(ab[0].ab3, 0);
    Bit#(24) a1b0 = msk(ab[1].ab0, 1); Bit#(24) a1b1 = msk(ab[1].ab1, 1);
    Bit#(24) a1b2 = msk(ab[1].ab2, 1); Bit#(24) a1b3 = msk(ab[1].ab3, 1);
    Bit#(24) a2b0 = msk(ab[2].ab0, 2); Bit#(24) a2b1 = msk(ab[2].ab1, 2);
    Bit#(24) a2b2 = msk(ab[2].ab2, 2);
    Bit#(24) a3b0 = msk(ab[3].ab0, 3); Bit#(24) a3b1 = msk(ab[3].ab1, 3);
    Bit#(24) a3b2 = msk(ab[3].ab2, 3);
    Bit#(24) a4b0 = msk(ab[4].ab0, 4); Bit#(24) a4b1 = msk(ab[4].ab1, 4);
    Bit#(24) a5b0 = msk(ab[5].ab0, 5); Bit#(24) a5b1 = msk(ab[5].ab1, 5);
    Bit#(24) a6b0 = msk(ab[6].ab0, 6);
    Bit#(24) a7b0 = msk(ab[7].ab0, 7);

    Bit#(33) a01_b0 = zeroExtend(a0b0) + zeroExtend({a1b0, 8'd0});
    Bit#(33) a23_b0 = zeroExtend(a2b0) + zeroExtend({a3b0, 8'd0});
    Bit#(33) a45_b0 = zeroExtend(a4b0) + zeroExtend({a5b0, 8'd0});
    Bit#(33) a67_b0 = zeroExtend(a6b0) + zeroExtend({a7b0, 8'd0});
    Bit#(33) a01_b1 = zeroExtend(a0b1) + zeroExtend({a1b1, 8'd0});
    Bit#(33) a23_b1 = zeroExtend(a2b1) + zeroExtend({a3b1, 8'd0});
    Bit#(33) a45_b1 = zeroExtend(a4b1) + zeroExtend({a5b1, 8'd0});
    Bit#(33) a01_b2 = zeroExtend(a0b2) + zeroExtend({a1b2, 8'd0});
    Bit#(33) a23_b2 = zeroExtend(a2b2) + zeroExtend({a3b2, 8'd0});
    Bit#(33) a01_b3 = zeroExtend(a0b3) + zeroExtend({a1b3, 8'd0});

    Bit#(34) add_a01_b1_a23_b0 = zeroExtend(a01_b1)       + zeroExtend(a23_b0);
    Bit#(34) add_a01_b2_a45_b0 = zeroExtend(a01_b2)       + zeroExtend(a45_b0);
    Bit#(17) add_a01_b3_a23_b2 = zeroExtend(a01_b3[15:0]) + zeroExtend(a23_b2[15:0]);
    Bit#(17) add_a45_b1_a67_b0 = zeroExtend(a45_b1[15:0]) + zeroExtend(a67_b0[15:0]);

    Bit#(51) sum0 = (zeroExtend(add_a01_b1_a23_b0) << 16) + zeroExtend(a01_b0);
    Bit#(35) sum1 = zeroExtend(add_a01_b2_a45_b0)         + zeroExtend(a23_b1);
    Bit#(17) sum2 = zeroExtend(add_a01_b3_a23_b2[15:0])   + zeroExtend(add_a45_b1_a67_b0[15:0]);

    Bit#(36) half_sum1 = {zeroExtend(sum2[15:0]), 16'd0} + zeroExtend(sum1);
    Bit#(65) sum       = zeroExtend(sum0) + zeroExtend({half_sum1[31:0], 32'd0});

    return sum[64:50];
endfunction

(* synthesize *)
module mkHashTable(HashTable_Ifc);
    Vector#(8, BRAM1Port#(Bit#(15), Bit#(1))) ht_brams <- genWithM(
        \genBRAM (Integer l) -> begin
            BRAM_Configure c = defaultValue;
            c.loadFormat = tagged Hex ("ht_" + integerToString(l) + ".mif");
            mkBRAM1Server(c);
        end
    );

    FIFOF#(Bit#(8)) out_fifo <- mkFIFOF();

    // for delay
    Vector#(6, FIFOF#(Vector#(8, Vector#(8, MulHashOut)))) stage_fifo <- replicateM(mkFIFOF());
    FIFOF#(Bit#(0)) bram_pipe <- mkFIFOF();

    for (Integer s = 0; s < 5; s = s + 1)
        rule do_pipe_shift;
            let d <- toGet(stage_fifo[s]).get();
            stage_fifo[s+1].enq(d);
        endrule

    rule do_acc_hash;
        let mul_results <- toGet(stage_fifo[5]).get();
        for (Integer l = 0; l < 8; l = l + 1) begin
            Bit#(15) addr = acc_hash(mul_results[l], fromInteger(l));
            ht_brams[l].portA.request.put(BRAMRequest{
                write           : False,
                responseOnWrite : False,
                address         : addr,
                datain          : ?
            });
        end
        bram_pipe.enq(?);
    endrule

    rule do_bram_resp;
        bram_pipe.deq();
        Bit#(8) ht_result = 0;
        for (Integer l = 0; l < 8; l = l + 1) begin
            let bit_val <- ht_brams[l].portA.response.get();
            ht_result[l] = bit_val[0];
        end
        out_fifo.enq(ht_result);
    endrule

    method Action put(Bit#(64) window);
        Vector#(8, Vector#(8, MulHashOut)) mul_results = newVector();
        for (Integer l = 0; l < 8; l = l + 1) begin
            mul_results[l] = newVector();
            for (Integer i = 0; i < 8; i = i + 1) begin
                Bit#(8) byte_val = (i <= l) ? window[i*8+7 : i*8] : 0;
                mul_results[l][i] = mul_hash(byte_val);
            end
        end
        stage_fifo[0].enq(mul_results);
    endmethod

    method ActionValue#(Bit#(8)) get();
        out_fifo.deq();
        return out_fifo.first();
    endmethod

endmodule

// genWithM 헬퍼: Integer 인덱스를 받아 모듈을 생성하는 Vector 생성기
module genWithM#(function module#(t) f(Integer i))(Vector#(n, t))
    provisos (Add#(1, _a, n));
    Vector#(n, t) result = newVector();
    for (Integer k = 0; k < valueOf(n); k = k + 1)
        result[k] <- f(k);
    return result;
endmodule

endpackage
